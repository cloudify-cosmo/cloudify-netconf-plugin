# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from cloudify import exceptions as cfy_exc
from lxml import etree
from lxml import isoschematron


NETCONF_NAMESPACE = "urn:ietf:params:xml:ns:netconf:base:1.0"
RELAXNG_NAMESPACE = 'http://relaxng.org/ns/structure/1.0'

# default netconf namespace short name
DEFAULT_NCNS = "rfc6020"


def _node_name(name, namespace, xmlns):
    attibute = False
    tag_namespace = namespace
    if "@" in name:
        spilted_names = name.split("@")
        if len(spilted_names) == 2:
            # tag with namespace
            tag_namespace = spilted_names[0]
            name = spilted_names[1]
        else:
            if len(spilted_names) == 3 and spilted_names[0] == '_':
                # attibute with namespace
                tag_namespace = spilted_names[1]
                name = spilted_names[2]
                attibute = True
            else:
                # i dont know what is it
                raise cfy_exc.NonRecoverableError(
                    "wrong format of xml element name"
                )
    # looks as empty namespace
    if tag_namespace == "":
        tag_namespace = namespace
    # replace to real ns
    if tag_namespace in xmlns:
        # we can use such namespace
        return attibute, tag_namespace, "{%s}%s" % (xmlns[tag_namespace], name)
    else:
        # we dont have such namespace
        return attibute, tag_namespace, name


def _general_node(parent, node_name, value, xmlns, namespace, nsmap):
    # harcoded magic value for case when we need set attributes to some tag
    # with text value inside
    if node_name == "_@@":
        parent.text = str(value)
        return
    # general logic
    attribute, tag_namespace, tag_name = _node_name(
        node_name, namespace, xmlns
    )
    # attibute can't contain complicated values, ignore attribute flag
    # for now
    if not attribute or isinstance(value, dict):
        # can be separate node
        result = etree.Element(
            tag_name, nsmap=nsmap
        )
        if isinstance(value, dict):
            _gen_xml(result, value, xmlns, tag_namespace, nsmap)
        else:
            if value is not None:
                # dont add None value
                result.text = str(value)
        parent.append(result)
    else:
        # attibute
        parent.attrib[tag_name] = str(value)


def _gen_xml(parent, properties, xmlns, namespace, nsmap):
    for node in properties:
        if isinstance(properties[node], list):
            # will be many nodes with same name
            for value in properties[node]:
                _general_node(
                    parent, node, value, xmlns, namespace, nsmap
                )
        else:
            _general_node(
                parent, node, properties[node], xmlns, namespace, nsmap
            )


def update_xmlns(xmlns):
    netconf_namespace = DEFAULT_NCNS
    for k in xmlns:
        if xmlns[k] == NETCONF_NAMESPACE:
            netconf_namespace = k
            break
    if netconf_namespace not in xmlns:
        xmlns[netconf_namespace] = NETCONF_NAMESPACE
    return netconf_namespace, xmlns


def create_nsmap(xmlns):
    netconf_namespace, xmlns = update_xmlns(xmlns)
    nsmap = {}
    for k in xmlns:
        if k != "_":
            nsmap[k] = xmlns[k]
        else:
            nsmap[None] = xmlns[k]
    return nsmap, netconf_namespace, xmlns


def generate_xml_node(model, xmlns, parent_tag):
    if not xmlns:
        raise cfy_exc.NonRecoverableError(
            "node doesn't have any namespaces"
        )
    nsmap, netconf_namespace, xmlns = create_nsmap(xmlns)
    # we does not support attibutes on top level,
    # so for now ignore attibute flag
    _, _, tag_name = _node_name(parent_tag, netconf_namespace, xmlns)
    parent = etree.Element(
        tag_name, nsmap=nsmap
    )
    _gen_xml(parent, model, xmlns, '_', nsmap)
    return parent


def rpc_gen(message_id, operation, netconf_namespace, data, xmlns):
    if "@" in operation:
        action_name = operation
    else:
        action_name = netconf_namespace + "@" + operation
    new_node = {
        action_name: data,
        "_@" + netconf_namespace + "@message-id": message_id
    }
    return generate_xml_node(
        new_node,
        xmlns,
        'rpc'
    )


def _get_free_ns(xmlns, namespace, prefered_ns=None):
    """search some not existed namespace name, ands save namespace"""
    # search maybe we have some cool name for it
    namespace_name = None
    if prefered_ns:
        for ns in prefered_ns:
            if ns is not None and prefered_ns[ns] == namespace:
                # we have some short and cool name
                namespace_name = ns
                break
    # we dont have cool names, create ugly
    if not namespace_name:
        namespace_name = "_" + namespace.replace(":", "_")
        namespace_name = namespace_name.replace("/", "_")
    # save uniq for namespace name
    while namespace_name in xmlns:
        namespace_name = "_" + namespace_name + "_"
    xmlns[namespace_name] = namespace
    return namespace_name


def _short_names(name, xmlns, nsmap=None):
    if name[0] != "{":
        return name
    for ns_short in xmlns:
        fullnamespace = "{" + xmlns[ns_short] + "}"
        if fullnamespace in name:
            if not ns_short or ns_short == '_':
                return name.replace(fullnamespace, "")
            else:
                return name.replace(fullnamespace, ns_short + "@")
    # we dont have such namespace,
    # in any case we will have } in string if we have used lxml
    namespace = name[1:]
    name = namespace[namespace.find("}") + 1:]
    namespace = namespace[:namespace.find("}")]
    return _get_free_ns(xmlns, namespace, nsmap) + "@" + name


def _node_to_dict(parent, xml_node, xmlns):
    name = _short_names(xml_node.tag, xmlns, xml_node.nsmap)
    if not xml_node.getchildren() and not xml_node.attrib:
        # we dont support text inside of node
        # if we have subnodes or attibutes
        value = xml_node.text
    else:
        value = {}
        if xml_node.text and len(xml_node.text.strip()):
            value["_@@"] = xml_node.text.strip()
        for i in xml_node.getchildren():
            _node_to_dict(value, i, xmlns)
        for k in xml_node.attrib:
            k_short = _short_names(k, xmlns, xml_node.nsmap)
            if '@' in k_short:
                # already have namespace
                k_short = "_@" + k_short
            else:
                # we dont have namespace yet
                k_short = "_@@" + k_short
            value[k_short] = xml_node.attrib[k]
    if name in parent:
        previous = parent[name]
        if isinstance(previous, list):
            parent[name].append(value)
        else:
            parent[name] = [previous, value]
    else:
        parent[name] = value


def generate_dict_node(parent, xml_node, nslist):
    netconf_namespace, xmlns = update_xmlns(nslist)
    _node_to_dict(parent, xml_node, xmlns)


def xml_repack_node(xml_node):
    # we have some issues with relaxng top node validation
    # so we try to repack xml node
    node_text = etree.tostring(
        xml_node, pretty_print=False
    )
    return etree.XML(node_text)


# def xml_repack_text(node_text):
#    # we have some issues with relaxng top node validation
#    # so we try to repack xml node
#    xml_node = etree.XML(node_text)
#    return etree.tostring(
#        xml_node, pretty_print=False
#    )


def _xml_validate_node(node, relaxng, schematron):
    if relaxng:
        if not relaxng.validate(xml_repack_node(node)):
            raise cfy_exc.NonRecoverableError(
                "Not valid xml by rng\n reason:" + str(
                    relaxng.error_log.last_error
                )
            )
    if schematron:
        if not schematron.validate(node):
            raise cfy_exc.NonRecoverableError(
                "Not valid xml by Schematron"
            )


def xml_validate(parent, xmlns, xpath=None, rng=None, sch=None):
    """Validate xml by rng and sch"""

    if xpath:

        # rng rules
        relaxng = None
        if rng:
            rng_node = etree.XML(rng)
            relaxng = etree.RelaxNG(rng_node)

        # schematron rules
        schematron = None
        if sch:
            sch_node = etree.XML(sch)
            schematron = isoschematron.Schematron(sch_node)

        # run validation selected by xpath nodes
        for node in parent.xpath(xpath, namespaces=xmlns):
            _xml_validate_node(node, relaxng, schematron)


# relaxng specific parts
def load_xml(path):
    """load xml file, without any checks for errors"""
    rng_rpc = open(path, 'rb')
    with rng_rpc:
        return etree.XML(rng_rpc.read())


def default_xmlns():
    """default namespace list for relaxng"""
    return {
        '_': NETCONF_NAMESPACE,
        'relaxng': RELAXNG_NAMESPACE
    }


def _make_node_copy(xml_orig, nsmap):
    """copy nodes with namespaces from parent"""
    clone_nsmap = {}
    for ns in nsmap:
        clone_nsmap[ns] = nsmap[ns]
    for ns in xml_orig.nsmap:
        clone_nsmap[ns] = xml_orig.nsmap[ns]
    clone = etree.Element(
        xml_orig.tag, nsmap=clone_nsmap
    )
    for tag in xml_orig.attrib:
        clone.attrib[tag] = xml_orig.attrib[tag]
    for node in xml_orig.getchildren():
        clone.append(_make_node_copy(node, clone_nsmap))
    clone.text = xml_orig.text
    return clone


def load_relaxng_includes(xml_node, xmlns, replaces_files=None):
    """will replace all includes by real content"""
    if not replaces_files:
        replaces_files = {}
    nodes = xml_node.xpath('.//relaxng:include', namespaces=xmlns)
    grammar_name = "{" + RELAXNG_NAMESPACE + "}grammar"
    while len(nodes):
        for node in nodes:
            parent = node.getparent()
            if parent is not None:
                parent.remove(node)
                if 'href' in node.attrib:
                    if node.attrib['href'] in replaces_files:
                        subnodes = replaces_files[node.attrib['href']]
                    else:
                        subnodes = load_xml(node.attrib['href'])
                    if subnodes.tag == grammar_name:
                        for subnode in subnodes.getchildren():
                            parent.append(
                                _make_node_copy(subnode, subnodes.nsmap)
                            )
        nodes = xml_node.xpath('.//relaxng:include', namespaces=xmlns)
