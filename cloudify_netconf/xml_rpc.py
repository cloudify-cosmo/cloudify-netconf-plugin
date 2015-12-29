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
from cloudify import ctx
from cloudify.decorators import operation
from lxml import etree
import utils


@operation
def run(**kwargs):
    properties = ctx.node.properties
    operation = kwargs.get('action', 'get-config')
    data = kwargs.get('payload', {})
    parent = utils.generate_xml_node(
        data,
        properties.get('metadata', {}).get('xmlns'),
        operation,
        'rpc',
        11
    )
    ctx.logger.info(etree.tostring(
        parent, pretty_print=True, xml_declaration=True, encoding='UTF-8'
    ))
    xml_text = etree.tostring(
        parent, xml_declaration=True, encoding='UTF-8'
    )
    xml_node = etree.fromstring(xml_text)
    xml_dict = {}
    utils.generate_dict_node(
        xml_dict, xml_node,
        properties.get('metadata', {}).get('xmlns')
    )
    ctx.logger.info(str(xml_dict))
