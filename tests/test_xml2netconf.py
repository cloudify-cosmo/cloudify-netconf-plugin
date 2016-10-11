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
from cloudify import mocks as cfy_mocks
from cloudify.state import current_ctx
import cloudify_netconf.netconf_connection as netconf_connection
import cloudify_netconf.utils as utils
import cloudify_netconf.xml2netconf as xml2netconf
import mock
import unittest


class Xml2NetConfTest(unittest.TestCase):

    CORRECT_REPLY = """
        <rpc-reply
            xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
            xmlns:ns0="urn:ietf:params:xml:ns:netconf:base:1.0"
            xmlns:turing="http://example.net/turing-machine"
            xmlns:t2="http://example.net/turing-machine/tape-2"
            ns0:message-id="57380">
            <ok/>
        </rpc-reply>
    """

    def tearDown(self):
        current_ctx.clear()

    def test_convert(self):
        fake_ctx = cfy_mocks.MockCloudifyContext()
        instance = mock.Mock()
        instance.runtime_properties = {}
        fake_ctx._instance = instance
        node = mock.Mock()
        fake_ctx._node = node
        node.properties = {}
        node.runtime_properties = {}

        # no xmls
        current_ctx.set(fake_ctx)
        xml2netconf.run(ctx=fake_ctx)
        self.assertEqual(instance.runtime_properties, {})

        # more real call, but without xml
        xml2netconf.run(ctx=fake_ctx, xmls=[{'save_to': 'a'}])
        self.assertEqual(instance.runtime_properties, {})

        # lets use xml
        xml2netconf.run(ctx=fake_ctx, xmls=[{
            'save_to': 'a',
            'raw': self.CORRECT_REPLY
        }])
        self.assertEqual(instance.runtime_properties, {
            'a': {
                'rfc6020@rpc-reply': {
                    '_@rfc6020@message-id': '57380',
                    'rfc6020@ok': None
                }
            },
            'a_ns': {
                'rfc6020': 'urn:ietf:params:xml:ns:netconf:base:1.0'
            }
        })


