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
import time

def _generate_hello(xmlns):
    hello_dict = {
            'rfc6020@capabilities': {
                'rfc6020@capability': [
                    'urn:ietf:params:netconf:base:1.0',
                    'http://example.net/turing-machine?module=turing-machine&revision=2013-12-27'
                ]
            }
        }

    hello_xml = utils.generate_xml_node(
        hello_dict,
        xmlns,
        'rfc6020@hello'
    )
    return etree.tostring(
        hello_xml, pretty_print=True, xml_declaration=True, encoding='UTF-8'
    )

def _generate_goodbye(xmlns, message_id):
    goodbye_dict = {
        'rfc6020@close-session': None,
        '_@@message-id': message_id
    }
    goodbye_xml = utils.generate_xml_node(
        goodbye_dict,
        xmlns,
        'rfc6020@rpc'
    )
    return etree.tostring(
        goodbye_xml, pretty_print=True, xml_declaration=True, encoding='UTF-8'
    )

@operation
def run(**kwargs):

    message_id = int((time.time() * 100) % 100 * 1000)

    properties = ctx.node.properties
    operation = kwargs.get('action', 'get-config')
    if not 'action' in kwargs:
        ctx.logger.info("No operations")
        return
    data = kwargs.get('payload', {})
    netconf_namespace, xmlns = utils.update_xmlns(
        properties.get('metadata', {}).get('xmlns')
    )

    # connect
    ctx.logger.info(properties.get('netconf_auth'))
    hello_string = _generate_hello(xmlns)
    ctx.logger.info("i sent: " + hello_string)
    capabilities, ssh, chan, buff = utils.connect_to_netconf(
        properties.get('netconf_auth', {}).get('ip'),
        properties.get('netconf_auth', {}).get('user'),
        properties.get('netconf_auth', {}).get('password'),
        hello_string
    )
    ctx.logger.info("i recieved: " + capabilities)

    # rpc
    ctx.logger.info("rpc call")
    message_id = message_id + 1
    if "@" in operation:
        action_name = operation
    else:
        action_name = netconf_namespace + "@" + operation
    new_node = {
        action_name : data,
        "_@@message-id": message_id
    }
    parent = utils.generate_xml_node(
        new_node,
        xmlns,
        'rpc'
    )
    rpc_string = etree.tostring(
        parent, pretty_print=True, xml_declaration=True, encoding='UTF-8'
    )
    ctx.logger.info("i sent: " + rpc_string)
    buff, response = utils.send_xml(chan, buff, rpc_string)
    ctx.logger.info("i recieved:" + response)

    #goodbye
    ctx.logger.info("connection close")
    message_id = message_id + 1
    goodbye_string = _generate_goodbye(xmlns, message_id)
    ctx.logger.info("i sent: " + goodbye_string)

    buff, response = utils.close_connection(chan, ssh, buff, goodbye_string)
    ctx.logger.info("i recieved: " + response)
