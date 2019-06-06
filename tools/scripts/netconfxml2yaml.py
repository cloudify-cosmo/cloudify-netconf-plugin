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
import sys
import yaml

help_message = """
usage: python netconfxml2yaml.py rpc.xml

In rpc.xml:
-------------------
<?xml version='1.0' encoding='UTF-8'?>
<rpc xmlns:turing="http://example.net/turing-machine"
    xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="some_id">
  <get>
    <filter type="subtree">
      <turing:turing-machine>
        <turing:transition-function/>
      </turing:turing-machine>
    </filter>
    <source>
      <running/>
    </source>
  </get>
</rpc>
-------------------
"""
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(help_message)
    else:
        xmlns = utils.default_xmlns()
        xml_node = utils.load_xml(sys.argv[1])
        rng = None
        xml_dict = {}
        utils.generate_dict_node(
            xml_dict, xml_node,
            xmlns
        )
        result = {
            'payload': xml_dict,
            'ns': xmlns
        }
        print(yaml.dump(result))
