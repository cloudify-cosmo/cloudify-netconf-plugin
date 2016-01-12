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
import cloudify_netconf.utils as utils
from lxml import etree
from lxml import isoschematron
import sys
import yaml
from StringIO import StringIO

help_message = """
usage: python netconfxml2yaml.py rpc.xml [rpc.rng [rpc.sch]]

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
    if len(sys.argv) < 2 and len(sys.argv) > 4:
        print(help_message)
    else:
        xml_rpc = open(sys.argv[1], 'rb')
        with xml_rpc:
            xmlns = {
                '_': utils.NETCONF_NAMESPACE
            }
            xml_text = xml_rpc.read()
            xml_node = etree.XML(xml_text)
            rng = None
            if len(sys.argv) > 2:
                rng_rpc = open(sys.argv[2], 'rb')
                with rng_rpc:
                    data = StringIO(rng_rpc.read())
                    tree = etree.parse(data)
                    tree.xinclude()
                    rng = tree.getroot()
                    #rng = etree.XML(rng_rpc.read())
            if rng is not None:
                relaxng = etree.RelaxNG(rng)
                if not relaxng.validate(xml_node):
                    print ("You have issues with relaxng")
            sch = None
            if len(sys.argv) > 3:
                sch_rpc = open(sys.argv[3], 'rb')
                with sch_rpc:
                    sch = etree.XML(sch_rpc.read())
            if sch is not None:
                schematron = isoschematron.Schematron(sch)
                if not schematron.validate(xml_node):
                    print ("You have issues with Schematron")
            xml_dict = {}
            utils.generate_dict_node(
                xml_dict, xml_node,
                xmlns
            )
            result = {
                'payload': xml_dict,
                'ns': xmlns
            }
            if rng is not None:
                result['rng'] = etree.tostring(
                    rng, pretty_print=False, xml_declaration=True,
                    encoding='UTF-8'
                )
            if sch is not None:
                result['sch'] = etree.tostring(
                    sch, pretty_print=False, xml_declaration=True,
                    encoding='UTF-8'
                )
            print(yaml.dump(result))
