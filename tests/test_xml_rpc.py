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

    def tearDown(self):
        current_ctx.clear()

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

        # without backend db
        base = {}
        rpc._update_data(base, "rfc6020@edit-config", "a", None)
        self.assertEqual(base, {})

    def _get_fake_nc_connect(self):
        """netconf connection mock"""
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

        return nc_conn

    def test__search_error(self):
        """check deep search"""
        # we have text as node value
        rpc._search_error("Some Line", '?')

        # we have some list as node
        rpc._search_error(["Some Line"], '?')

        rpc._search_error([{"node_name": "Some Line"}], '?')

        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._search_error([{"rpc-error": {}}], '?')

        # we have some dict as node
        rpc._search_error({"node_name": "Some Line"}, '?')

        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._search_error({"a": {"rpc-error": {}}}, '?')

        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._search_error({"a": [{"rpc-error": {}}]}, '?')

        rpc._search_error({
            "a": [{
                "rpc-error": [{
                    'error-severity': 'warning'
                }]
            }]
        }, '?')

        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._search_error({
                "a": [{
                    "rpc-error": [{
                        'error-severity': 'error'
                    }]
                }]
            }, '?')

        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._search_error({
                "a": [{
                    "b@rpc-error": [{
                        'b@error-severity': 'error'
                    }]
                }]
            }, '?')

    def test_parse_response(self):
        """check parse response code"""
        xml = self.CORRECT_REPLY
        netconf_namespace, xmlns = utils.update_xmlns({})
        response = rpc._parse_response(xmlns, netconf_namespace, xml, True)
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
        response = rpc._parse_response(xmlns, netconf_namespace, xml, True)
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
            rpc._parse_response(xmlns, netconf_namespace, xml, True)

        # error in reply
        xml = """
            <rpc-reply message-id="57380">
                <rpc-error/>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._parse_response(xmlns, netconf_namespace, xml, True)

        # warning in reply
        xml = """
            <rpc-reply message-id="57380">
                <rpc-error>
                    <error-severity>warning</error-severity>
                </rpc-error>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        rpc._parse_response(xmlns, netconf_namespace, xml, True)

        # error in reply
        xml = """
            <rpc-reply message-id="57380">
                <rpc-error>
                    <error-severity>error</error-severity>
                </rpc-error>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._parse_response(xmlns, netconf_namespace, xml, True)

        # error in reply in uncommon place
        xml = """
            <rpc-reply message-id="57380">
                <uncommon>
                    <rpc-error>
                        <error-severity>error</error-severity>
                    </rpc-error>
                </uncommon>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._parse_response(
                xmlns, netconf_namespace, xml, True, True
            )

        # error in reply with namespace
        xml = """
            <rpc-reply
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                message-id="57380">
                <rpc-error/>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._parse_response(xmlns, netconf_namespace, xml, True)

        # warning in reply with namespace
        xml = """
            <rpc-reply
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                message-id="57380">
                <rpc-error>
                    <error-severity>warning</error-severity>
                </rpc-error>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        rpc._parse_response(xmlns, netconf_namespace, xml, True)

        # error in reply in uncommon place with namespace
        xml = """
            <rpc-reply
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                message-id="57380">
                <uncommon>
                    <rpc-error>
                        <error-severity>error</error-severity>
                    </rpc-error>
                </uncommon>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.RecoverableError):
            rpc._parse_response(
                xmlns, netconf_namespace, xml, True, True
            )

        # check issues with xml
        xml = """
            <rpc-reply
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                xmlns:junos="http://xml.juniper.net/junos/12.1X46/junos"
                xmlns:junos="http://xml.juniper.net/junos/12.1X46/junos"
                xmlns:rfc6020="urn:ietf:params:xml:ns:netconf:base:1.0"
                xmlns:xnm="http://xml.juniper.net/xnm/1.1/xnm"
                rfc6020:message-id="229">
                    <ok/>
            </rpc-reply>
        """
        netconf_namespace, xmlns = utils.update_xmlns({})
        response = rpc._parse_response(xmlns, netconf_namespace, xml, False)
        self.assertEqual(
            response, {
                'rfc6020@ok': None,
                '_@rfc6020@message-id': '229'
            }
        )

        # raise execption for uncorrect xml
        netconf_namespace, xmlns = utils.update_xmlns({})
        with self.assertRaises(cfy_exc.NonRecoverableError):
            rpc._parse_response(xmlns, netconf_namespace, xml, True)

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

    def _get_mock_context_for_run(self):
        fake_ctx = cfy_mocks.MockCloudifyContext()
        instance = mock.Mock()
        instance.runtime_properties = {}
        fake_ctx._instance = instance
        node = mock.Mock()
        fake_ctx._node = node
        node.properties = {}
        node.runtime_properties = {}
        fake_ctx.get_resource = mock.MagicMock(
            return_value=""
        )
        return fake_ctx, node, instance

    def test_run_templates(self):
        # check template engine
        fake_ctx, _, _ = self._get_mock_context_for_run()
        nc_conn = self._get_fake_nc_connect()

        current_ctx.set(fake_ctx)

        rpc._run_templates(
            nc_conn, ['{{ a }}'], {'a': 'correct'}, "rfc6020",
            {"rfc6020": "urn:ietf:params:xml:ns:netconf:base:1.0"},
            False, False, None  # no check/no logs
        )

        nc_conn.send.assert_called_with(
            'correct'
        )

    def test_run_with_template(self):
        """check connect/call rpc/close connection calls sequence"""
        fake_ctx, node, instance = self._get_mock_context_for_run()

        hello_message = (
            """<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<rfc6020""" +
            """:hello xmlns:a="b" xmlns:d="c" xmlns:rfc6020="urn:ie""" +
            """tf:params:xml:ns:netconf:base:1.0">\n  <rfc6020:capa""" +
            """bilities>\n    <rfc6020:capability>urn:ietf:params:n""" +
            """etconf:base:1.0</rfc6020:capability>\n    <rfc6020:c""" +
            """apability>urn:ietf:params:netconf:base:1.1</rfc6020:""" +
            """capability>\n  </rfc6020:capabilities>\n</rfc6020:he""" +
            """llo>\n"""
        )

        # no calls
        current_ctx.set(fake_ctx)

        # with empty list of calls
        rpc.run(ctx=fake_ctx, template=None)
        rpc.run(ctx=fake_ctx, template="")

        # with list of calls, but without auth
        with self.assertRaises(cfy_exc.NonRecoverableError):
            rpc.run(ctx=fake_ctx, template="template.xml")

        nc_conn = self._get_fake_nc_connect()

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
            rpc.run(ctx=fake_ctx, template="template.xml")
            nc_conn.connect.assert_called_with(
                'super_secret', 'me', hello_message, 'secret', None, 830
            )

            fake_ctx.get_resource.assert_called_with(
                "template.xml"
            )

            # have some params
            fake_ctx.get_resource = mock.MagicMock(
                return_value="{{ a }}"
            )

            # empty params
            rpc.run(
                ctx=fake_ctx, template="template.xml", params={}
            )

            # real params
            rpc.run(
                ctx=fake_ctx, template="template.xml", params={'a': 'b'}
            )

            # template with empty commands, must be skiped
            fake_ctx.get_resource = mock.MagicMock(
                return_value="]]>]]>\n]]>]]>"
            )
            rpc.run(
                ctx=fake_ctx, template="template.xml", params={'a': 'b'}
            )

    def test_run_with_calls(self):
        """check connect/call rpc/close connection calls sequence"""
        fake_ctx, node, instance = self._get_mock_context_for_run()

        hello_message = (
            """<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n<rfc6020""" +
            """:hello xmlns:a="b" xmlns:d="c" xmlns:rfc6020="urn:ie""" +
            """tf:params:xml:ns:netconf:base:1.0">\n  <rfc6020:capa""" +
            """bilities>\n    <rfc6020:capability>urn:ietf:params:n""" +
            """etconf:base:1.0</rfc6020:capability>\n    <rfc6020:c""" +
            """apability>urn:ietf:params:netconf:base:1.1</rfc6020:""" +
            """capability>\n  </rfc6020:capabilities>\n</rfc6020:he""" +
            """llo>\n"""
        )

        # no calls
        current_ctx.set(fake_ctx)
        rpc.run(ctx=fake_ctx)

        # with empty list of calls
        rpc.run(ctx=fake_ctx, calls=[])

        # with list of calls, but without auth
        with self.assertRaises(cfy_exc.NonRecoverableError):
            rpc.run(ctx=fake_ctx, calls=[{'action': 'get'}])

        nc_conn = self._get_fake_nc_connect()

        node.properties = {
            'netconf_auth': {
                "user": "me",
                "password": "secret",
                "ip": "super_secret",
                # save logs
                "store_logs": True
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
            nc_conn.connect.assert_called_with(
                'super_secret', 'me', hello_message, 'secret', None, 830
            )
            fake_ctx.get_resource.assert_not_called()

            # have some payload
            rpc.run(
                ctx=fake_ctx, calls=[{
                    'action': 'run_something',
                    'payload': {
                        "a": "b"
                    }
                }]
            )

            # have lock/unlock operations
            rpc.run(
                ctx=fake_ctx, calls=[{
                    'action': 'run_something',
                    'payload': {
                        "a": "b"
                    }
                }],
                lock=["rfc6020@candidate"]
            )

            # have some copy operations
            rpc.run(
                ctx=fake_ctx, calls=[{
                    'action': 'run_something',
                    'payload': {
                        "a": "b"
                    }
                }],
                back_database="a", front_database="b"
            )

            # check save to runtime properties
            self.assertEqual(instance.runtime_properties, {})
            rpc.run(
                ctx=fake_ctx, calls=[{
                    'action': 'run_something',
                    'payload': {
                        "c": "d"
                    },
                    'validate_xml': False,
                    'save_to': 'd'
                }]
            )

            # looks as we save something
            self.assertTrue("d" in instance.runtime_properties)
            self.assertTrue("d_ns" in instance.runtime_properties)
            self.assertTrue(
                "rfc6020@ok" in instance.runtime_properties["d"]
            )

            self.assertEqual(
                nc_conn.current_level,
                netconf_connection.NETCONF_1_0_CAPABILITY
            )

        # version 1.1 and ip from cloudify.relationships.contained_in
        nc_conn.connect = mock.MagicMock(
            return_value=self.CORRECT_HELLO_1_1_REPLY
        )
        # drop ip from auth dict, lets use 'container' ip
        node.properties['netconf_auth']["ip"] = None
        instance.host_ip = "ip_from_runtime"
        with mock.patch(
            'cloudify_netconf.netconf_connection.connection',
            mock.MagicMock(return_value=nc_conn)
        ):
            rpc.run(ctx=fake_ctx, calls=[{
                'action': 'run_something',
            }])

            # we use correct ip from instance runtime properties
            nc_conn.connect.assert_called_with(
                'ip_from_runtime', 'me', hello_message, 'secret', None, 830
            )
            self.assertEqual(
                nc_conn.current_level,
                netconf_connection.NETCONF_1_1_CAPABILITY
            )

        nc_conn.connect = mock.MagicMock(
            return_value=self.CORRECT_HELLO_REPLY
        )
        with mock.patch(
            'cloudify_netconf.netconf_connection.connection',
            mock.MagicMock(return_value=nc_conn)
        ):
            node.properties['metadata']['dsdl'] = "<a></a>"

            transform_return = "<b>c</b>\n"
            transform_function = mock.MagicMock(
                return_value=transform_return
            )
            relaxng_mock = mock.MagicMock()
            schematron_mock = mock.MagicMock()
            # valid in any case
            relaxng_mock.validate = mock.MagicMock(
                return_value=True
            )
            schematron_mock.validate = mock.MagicMock(
                return_value=True
            )

            with mock.patch(
                'lxml.etree.XSLT', mock.MagicMock(
                    return_value=transform_function
                )
            ):
                with mock.patch(
                    'lxml.isoschematron.Schematron', mock.MagicMock(
                        return_value=schematron_mock
                    )
                ):
                    with mock.patch(
                        'lxml.etree.RelaxNG', mock.MagicMock(
                            return_value=relaxng_mock
                        )
                    ):
                        # have some payload with validatiuon
                        rpc.run(
                            ctx=fake_ctx, calls=[{
                                'action': 'run_something',
                                'payload': {
                                    "a": "b"
                                }
                            }]
                        )

    def test__write_to_log(self):
        # check that we dont die in case when we can't write log
        fake_ctx = cfy_mocks.MockCloudifyContext()
        current_ctx.set(fake_ctx)
        rpc._write_to_log("/proc/cpuinfo/error_file", "Message?")

    def test_gen_relaxng_with_schematron(self):
        # skip get config validation
        self.assertEqual(
            rpc._gen_relaxng_with_schematron(
                "<a></a>", "rfc6020@get-config"
            ),
            (None, None, None)
        )
        # edit config
        transform_return = "<b>c</b>\n"
        transform_function = mock.MagicMock(
            return_value=transform_return
        )
        with mock.patch(
            'lxml.etree.XSLT', mock.MagicMock(
                return_value=transform_function
            )
        ):
            self.assertEqual(
                rpc._gen_relaxng_with_schematron(
                    "<a></a>", "rfc6020@edit-config"
                ),
                (
                    transform_return, transform_return,
                    '/rfc6020:rpc/rfc6020:edit-config/rfc6020:config'
                )
            )
        # rpc
        transform_return = "<b>c</b>\n"
        transform_function = mock.MagicMock(
            return_value=transform_return
        )
        with mock.patch(
            'lxml.etree.XSLT', mock.MagicMock(
                return_value=transform_function
            )
        ):
            self.assertEqual(
                rpc._gen_relaxng_with_schematron(
                    "<a></a>", "rfc6020@some_rpc"
                ),
                (
                    transform_return, None, '/rfc6020:rpc'
                )
            )


if __name__ == '__main__':
    unittest.main()
