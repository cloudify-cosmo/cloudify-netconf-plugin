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


NETCONF_NAMESPACE = "urn:ietf:params:xml:ns:netconf:base:1.0"
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
    if tag_namespace in xmlns:
        # we can use such namespace
        return attibute, tag_namespace, "{%s}%s" % (xmlns[tag_namespace], name)
    else:
        # we dont have such namespace
        return attibute, tag_namespace, name


def _general_node(parent, node_name, value, xmlns, namespace, nsmap):
    attribute, tag_namespace, tag_name = _node_name(
        node_name, namespace, xmlns
    )
    # attibute can't content complicated values, ignore attibute flag for now
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


def _get_free_ns(xmlns, namespace):
    """search some not existed namespace name, ands save namespace"""
    namespace_name = "_" + namespace.replace(":", "_")
    while namespace_name in xmlns:
        namespace_name = "_" + namespace_name + "_"
    xmlns[namespace_name] = namespace
    return namespace


def _short_names(name, xmlns):
    if name[0] != "{":
        return name
    for ns_short in xmlns:
        fullnamespace = "{" + xmlns[ns_short] + "}"
        if fullnamespace in name:
            if not ns_short or ns_short == '_':
                return name.replace(fullnamespace, "")
            else:
                return name.replace(fullnamespace, ns_short + "@")
    # we dont have such namespace
    namespace = name[1:]
    if namespace.find("}"):
        name = namespace[namespace.find("}") + 1:]
        namespace = namespace[:namespace.find("}")]
        return _get_free_ns(xmlns, namespace) + "@" + name
    return name


def _node_to_dict(parent, xml_node, xmlns):
    name = _short_names(xml_node.tag, xmlns)
    if not xml_node.getchildren():
        # we dont support text inside of node if we have subnodes
        value = xml_node.text
    else:
        value = {}
        for i in xml_node.getchildren():
            _node_to_dict(value, i, xmlns)
        for k in xml_node.attrib:
            k_short = _short_names(k, xmlns)
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


def rpc_gen(message_id, operation, netconf_namespace, data, xmlns):
    if "@" in operation:
        action_name = operation
    else:
        action_name = netconf_namespace + "@" + operation
    new_node = {
        action_name: data,
        "_@@message-id": message_id
    }
    return generate_xml_node(
        new_node,
        xmlns,
        'rpc'
    )
