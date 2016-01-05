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
from cloudify import exceptions as cfy_exc
from lxml import etree
import utils
import netconf_connection
import time

DEFAULT_CAPABILITY = 'urn:ietf:params:netconf:base:1.0'



def _generate_hello(xmlns, netconf_namespace, capabilities):
    if not capabilities:
        capabilities = []
    if not DEFAULT_CAPABILITY in capabilities:
        capabilities.append(DEFAULT_CAPABILITY)
    hello_dict = {
        netconf_namespace + '@capabilities': {
            netconf_namespace + '@capability': capabilities
        }
    }

    hello_xml = utils.generate_xml_node(
        hello_dict,
        xmlns,
        netconf_namespace + '@hello'
    )
    return etree.tostring(
        hello_xml, pretty_print=True, xml_declaration=True, encoding='UTF-8'
    )


def _generate_goodbye(xmlns, netconf_namespace, message_id):
    goodbye_dict = {
        netconf_namespace + '@close-session': None,
        '_@@message-id': message_id
    }
    goodbye_xml = utils.generate_xml_node(
        goodbye_dict,
        xmlns,
        netconf_namespace + '@rpc'
    )
    return etree.tostring(
        goodbye_xml, pretty_print=True, xml_declaration=True, encoding='UTF-8'
    )


def _parse_response(xmlns, netconf_namespace, response):
    xml_node = etree.XML(response)
    xml_dict = {}
    utils.generate_dict_node(
        xml_dict, xml_node,
        xmlns
    )
    reply = None
    if 'rpc-reply' in xml_dict:
        reply = xml_dict['rpc-reply']
    elif (netconf_namespace + '@rpc-reply') in xml_dict:
        # default namespace can't be not netconf 1.0
        reply = xml_dict[netconf_namespace + '@rpc-reply']
    if not reply:
        raise cfy_exc.NonRecoverableError(
            "unexpected reply struct"
        )
    # error check
    error = None
    if 'rpc-error' in reply:
        error = reply['rpc-error']
    elif (netconf_namespace + '@rpc-error') in reply:
        # default namespace can't be not netconf 1.0
        error = reply[netconf_namespace + '@rpc-error']
    if error:
        raise cfy_exc.NonRecoverableError(
            "We have error in reply" + str(error)
        )
    return reply


@operation
def run(**kwargs):

    message_id = int((time.time() * 100) % 100 * 1000)

    properties = ctx.node.properties
    operation = kwargs.get('action')
    if not operation:
        ctx.logger.info("No operations")
        return
    data = kwargs.get('payload', {})
    xmlns = properties.get('metadata', {}).get('xmlns')
    netconf_namespace, xmlns = utils.update_xmlns(
        xmlns
    )
    capabilities = properties.get('metadata', {}).get('capabilities')

    # connect
    ctx.logger.info(properties.get('netconf_auth'))
    hello_string = _generate_hello(
        xmlns, netconf_namespace, capabilities
    )
    ctx.logger.info("i sent: " + hello_string)
    netconf = netconf_connection.connection()
    capabilities = netconf.connect(
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
        action_name: data,
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
    response = netconf.send(rpc_string)
    ctx.logger.info("i recieved:" + response)

    response_dict = _parse_response(xmlns, netconf_namespace, response)
    ctx.logger.info("package will be :" + str(response_dict))

    save_to = kwargs.get('save_to')
    if save_to:
        ctx.instance.runtime_properties[save_to] = response_dict
        ctx.instance.runtime_properties[save_to + "_ns"] = xmlns

    # goodbye
    ctx.logger.info("connection close")
    message_id = message_id + 1
    goodbye_string = _generate_goodbye(xmlns, netconf_namespace, message_id)
    ctx.logger.info("i sent: " + goodbye_string)

    response = netconf.close(goodbye_string)
    ctx.logger.info("i recieved: " + response)
