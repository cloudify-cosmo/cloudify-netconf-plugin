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
import cloudify_netconf.netconf_connection as netconf_connection
import cloudify_netconf.utils as utils
import cloudify_netconf.xml_rpc as rpc
import mock
import unittest


class XmlRpcTest(unittest.TestCase):

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

    CORRECT_HELLO_REPLY = """
        <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <capabilities>
                <capability>urn:ietf:params:netconf:base:1.0</capability>
            </capabilities>
        </hello>
    """

    CORRECT_HELLO_1_1_REPLY = """
        <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <capabilities>
                <capability>urn:ietf:params:netconf:base:1.0</capability>
                <capability>urn:ietf:params:netconf:base:1.1</capability>
            </capabilities>
        </hello>
    """

    CORRECT_CLOSE_REPLY = """
        <rpc-reply
            xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="14501">
            <ok/>
        </rpc-reply>
    """

    def test_generate_hello(self):
        """check hello message"""
        hello_message = (
            """<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<rfc6020""" +
            """:hello xmlns:rfc6020="urn:ietf:params:xml:ns:netconf""" +
            """:base:1.0">\n  <rfc6020:capabilities>\n    <rfc6020:""" +
            """capability>urn:ietf:params:netconf:base:1.0</rfc6020""" +
            """:capability>\n    <rfc6020:capability>urn:ietf:param""" +
            """s:netconf:base:1.1</rfc6020:capability>\n  </rfc6020""" +
            """:capabilities>\n</rfc6020:hello>\n"""
        )
        netconf_namespace, xmlns = utils.update_xmlns({})
        hello_string = rpc._generate_hello(xmlns, netconf_namespace, {})
        self.assertEqual(hello_string, hello_message)

    def test_generate_goodbye(self):
        """check goodbye message"""
        goodbye_message = (
            """<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<rfc6020""" +
            """:rpc xmlns:rfc6020="urn:ietf:params:xml:ns:netconf:b""" +
            """ase:1.0" message-id="last_message">\n  <rfc6020:clos""" +
            """e-session/>\n</rfc6020:rpc>\n"""
        )
        netconf_namespace, xmlns = utils.update_xmlns({})
        goodbye_string = rpc._generate_goodbye(
            xmlns, netconf_namespace, "last_message"
        )
        self.assertEqual(goodbye_string, goodbye_message)

    def test_update_data(self):
        """update target for edit-config"""
        # non edit config
        base = {}
        rpc._update_data(base, "non-edit-config", "a", "b")
        self.assertEqual(base, {})

        # already have target
        base = {
            "target": "c"
        }
        rpc._update_data(base, "rfc6020@edit-config", "a", "b")
        self.assertEqual(base, {'target': 'c'})

        # empty target
        base = {
            "target": {}
        }
        rpc._update_data(base, "rfc6020@edit-config", "a", "b")
        self.assertEqual(base, {'target': {'b': None}})

        # already have target
        base = {
            "a@target": "c"
        }
        rpc._update_data(base, "rfc6020@edit-config", "a", "b")
        self.assertEqual(base, {'a@target': 'c'})

        # empty target
        base = {
            "a@target": {}
        }
        rpc._update_data(base, "rfc6020@edit-config", "a", "b")
        self.assertEqual(base, {'a@target': {'b': None}})

        # without target
        base = {}
        rpc._update_data(base, "rfc6020@edit-config", "a", "b")
        self.assertEqual(base, {'a@target': {'b': None}})

    def test_parse_response(self):
        """check parse response code"""
        xml = self.CORRECT_REPLY
        netconf_namespace, xmlns = utils.update_xmlns({})
        response = rpc._parse_response(xmlns, netconf_namespace, xml)
        self.assertEqual(
            response, {
                '_@rfc6020@message-id': '57380',
                'rfc6020@ok': None
            }
        )
        self.assertEqual(
            xmlns, {
                netconf_namespace: utils.NETCONF_NAMESPACE
            }
        )

        # no namespace in reply
        xml = """
            <rpc-reply message-id="57380">
                <ok/>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        response = rpc._parse_response(xmlns, netconf_namespace, xml)
        self.assertEqual(
            response, {
                '_@@message-id': '57380',
                'ok': None
            }
        )
        self.assertEqual(
            xmlns, {
                netconf_namespace: utils.NETCONF_NAMESPACE
            }
        )

        # dont have reply
        xml = """
            <rpc message-id="57380">
                <ok/>
            </rpc>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.NonRecoverableError):
            rpc._parse_response(xmlns, netconf_namespace, xml)

        # error in reply
        xml = """
            <rpc-reply message-id="57380">
                <rpc-error/>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.NonRecoverableError):
            rpc._parse_response(xmlns, netconf_namespace, xml)

        # error in reply with namespace
        xml = """
            <rpc-reply
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                message-id="57380">
                <rpc-error/>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.NonRecoverableError):
            rpc._parse_response(xmlns, netconf_namespace, xml)

    def test_server_support_1_1(self):
        """check support 1.1 response from server"""
        netconf_namespace, xmlns = utils.update_xmlns({})
        self.assertFalse(
            rpc._server_support_1_1(
                xmlns, netconf_namespace, self.CORRECT_HELLO_REPLY
            )
        )
        self.assertTrue(
            rpc._server_support_1_1(
                xmlns, netconf_namespace, self.CORRECT_HELLO_1_1_REPLY
            )
        )

    def test_run(self):
        """check connect/call rpc/close connection sequence"""
        fake_ctx = cfy_mocks.MockCloudifyContext()
        instance = mock.Mock()
        instance.runtime_properties = {}
        fake_ctx._instance = instance
        node = mock.Mock()
        fake_ctx._node = node
        node.properties = {}
        node.runtime_properties = {}

        # no calls
        rpc.run(ctx=fake_ctx)

        # with empty list of calls
        rpc.run(ctx=fake_ctx, calls=[])

        # with list of calls, but without auth
        with self.assertRaises(cfy_exc.NonRecoverableError):
            rpc.run(ctx=fake_ctx, calls=[{'action': 'get'}])

        # netconf connection mock
        nc_conn = mock.Mock()
        nc_conn.connect = mock.MagicMock(
            return_value=self.CORRECT_HELLO_REPLY
        )
        nc_conn.send = mock.MagicMock(
            return_value=self.CORRECT_REPLY
        )
        nc_conn.close = mock.MagicMock(
            return_value=self.CORRECT_CLOSE_REPLY
        )

        nc_conn.current_level = netconf_connection.NETCONF_1_0_CAPABILITY

        node.properties = {
            'netconf_auth': {
                "user": "me",
                "password": "secret",
                "ip": "super_secret"
            },
            'metadata': {
                'xmlns': {
                    'd': 'c'
                }
            },
            "base_xmlns": {
                "a": "b"
            }
        }
        with mock.patch(
            'cloudify_netconf.netconf_connection.connection',
            mock.MagicMock(return_value=nc_conn)
        ):
            # we have empty action
            rpc.run(ctx=fake_ctx, calls=[{'unknow': 'get'}])

            # have some payload
            rpc.run(ctx=fake_ctx, calls=[{
                'action': 'run_something',
                'payload': {
                    "a": "b"
                }
            }])

            # have lock/unlock operations
            rpc.run(ctx=fake_ctx, calls=[{
                'action': 'run_something',
                'payload': {
                    "a": "b"
                }
            }], lock=["rfc6020@candidate"])

            # have some copy operations
            rpc.run(ctx=fake_ctx, calls=[{
                'action': 'run_something',
                'payload': {
                    "a": "b"
                }
            }], back_database="a", front_database="b")

            # check save to runtime properties
            self.assertEqual(instance.runtime_properties, {})
            rpc.run(ctx=fake_ctx, calls=[{
                'action': 'run_something',
                'payload': {
                    "c": "d"
                },
                'save_to': 'd'
            }])

            # looks as we save something
            self.assertTrue("d" in instance.runtime_properties)
            self.assertTrue("d_ns" in instance.runtime_properties)
            self.assertTrue(
                "rfc6020@ok" in instance.runtime_properties["d"]
            )

            # validation without relaxng
            rpc.run(ctx=fake_ctx, calls=[{
                'action': 'run_something',
                'payload': {
                    "c": "d"
                },
                'save_to': 'd',
                'validation': {
                    'xpath': 'somepath'
                }
            }])

            self.assertEqual(
                nc_conn.current_level,
                netconf_connection.NETCONF_1_0_CAPABILITY
            )

        # version 1.1
        nc_conn.connect = mock.MagicMock(
            return_value=self.CORRECT_HELLO_1_1_REPLY
        )
        with mock.patch(
            'cloudify_netconf.netconf_connection.connection',
            mock.MagicMock(return_value=nc_conn)
        ):
            rpc.run(ctx=fake_ctx, calls=[{
                'action': 'run_something',
            }])

            self.assertEqual(
                nc_conn.current_level,
                netconf_connection.NETCONF_1_1_CAPABILITY
            )

if __name__ == '__main__':
    unittest.main()
