# Copyright (c) 2015-2019 Cloudify Platform Ltd. All rights reserved
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
import cloudify_netconf.utils as utils
from lxml import etree
import sys
import yaml

from __future__ import print_function


help_message = """
usage: python yaml2netconfxml.py rpc.yaml

In rpc.yaml:
-------------------
ns:
  _: urn:ietf:params:xml:ns:netconf:base:1.0
  turing: http://example.net/turing-machine

action: get

payload:
  source:
    running: {}
  filter:
    _@@type: subtree
    turing@turing-machine:
      turing@transition-function: {}
-------------------
"""
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(help_message)
    else:
        yaml_rpc = open(sys.argv[1], 'rb')
        with yaml_rpc:
            yaml_text = yaml_rpc.read()
            yaml_dict = yaml.load(yaml_text)
            data = yaml_dict.get('payload', {})
            xmlns = yaml_dict.get('ns', {})
            operation = yaml_dict.get('action', 'get')
            netconf_namespace, xmlns = utils.update_xmlns(
                xmlns
            )
            parent = utils.rpc_gen(
                "some_id", operation, netconf_namespace, data, xmlns
            )
            rpc_string = etree.tostring(
                parent, pretty_print=True, xml_declaration=True,
                encoding='UTF-8'
            )
            print(rpc_string)
