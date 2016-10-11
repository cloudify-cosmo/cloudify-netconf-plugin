# Copyright (c) 2016 GigaSpaces Technologies Ltd. All rights reserved
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
from cloudify import ctx
from cloudify.decorators import operation
from lxml import etree
import cloudify_netconf.utils as utils


@operation
def run(**kwargs):
    """main entry point for all operations"""

    xmls = kwargs.get('xmls', [])
    if not xmls:
        ctx.logger.info("No xmls for translate")
        return

    xmlns = kwargs.get('xmlns', {})
    netconf_namespace, xmlns = utils.update_xmlns(
        xmlns
    )

    for xml_struct in xmls:
        raw_xml = xml_struct.get("raw")
        if not raw_xml:
            ctx.logger.info("Empty raw xml?")
            continue
        ctx.logger.info("Parsing %s..." % (raw_xml[:60]))
        xml_node = etree.XML(raw_xml)
        xml_dict = {}
        utils.generate_dict_node(
            xml_dict, xml_node,
            xmlns
        )
        # save results to runtime properties
        save_to = xml_struct.get('save_to')
        if save_to:
            ctx.instance.runtime_properties[save_to] = xml_dict
            ctx.instance.runtime_properties[save_to + "_ns"] = xmlns
