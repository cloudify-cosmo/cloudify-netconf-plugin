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
import cloudify_netconf.utils as utils
from lxml import etree
import mock
import unittest


class UtilsMockTest(unittest.TestCase):

    SIMPLE_DICT = {
        'a': {
            'b': {
                '_@@m': 'g',
                '_@@': 'b'
            },
            'c': {
                '_@nm@nm': 'update',
                'd': ['1', '2', '3']
            }
        }
    }

    # unexisted namespace, but it will block usage of such name in tests
    FAKE_NS = "turing"
    # and new name will be
    REAL_NS = "_turing_"

    TURING_DICT = {
        'rfc6020@rpc': {
            '_@@message-id': 'some_id',
            'rfc6020@get': {
                'rfc6020@filter': {
                    '_@@type': 'subtree',
                    REAL_NS + '@turing-machine': {
                        REAL_NS + '@transition-function': None
                    }
                },
                'rfc6020@source': {
                    'rfc6020@running': None
                }
            }
        }
    }

    # stripped version of turing xml
    TURING_STRIPPED = (
        """<rfc6020:rpc xmlns:rfc6020="urn:ietf:params:xml:ns:netco""" +
        """nf:base:1.0" xmlns:turing="a" xmlns:_turing_="http://exa""" +
        """mple.net/turing-machine"><rfc6020:rpc rfc6020:message-id""" +
        """="some_id"><rfc6020:get><rfc6020:source><rfc6020:running""" +
        """/></rfc6020:source><rfc6020:filter rfc6020:type="subtree""" +
        """"><_turing_:turing-machine><_turing_:transition-function""" +
        """/></_turing_:turing-machine></rfc6020:filter></rfc6020:g""" +
        """et></rfc6020:rpc></rfc6020:rpc>"""
    )

    def test_xml_to_dict_net_namespace(self):
        """test create new namespace shortname"""
        xml = """
            <a
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
            >
                <b xmlns="something">b</b>
            </a>
        """
        xmlns = {
            "_": utils.NETCONF_NAMESPACE
        }
        result = {}
        utils.generate_dict_node(result, etree.XML(xml), xmlns)
        # check dict
        self.assertEqual(
            {'a': {'_something@b': 'b'}},
            result
        )
        # check xmlns
        self.assertEqual(
            {
                '_': utils.NETCONF_NAMESPACE,
                '_something': 'something'
            }, xmlns
        )

    def test_xml_to_dict(self):
        """test minimal struct with tag list and attibutes"""
        xml = """
            <a
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                xmlns:nm="s"
            >
                <b m="g">
                    b
                </b>
                <c nm:nm="update">
                    <d>1</d>
                    <d>2</d>
                    <d>3</d>
                </c>
            </a>
        """
        xmlns = {
            "_": utils.NETCONF_NAMESPACE
        }
        result = {}
        utils.generate_dict_node(result, etree.XML(xml), xmlns)
        # check dict
        self.assertEqual(
            self.SIMPLE_DICT,
            result
        )
        # check xmlns
        self.assertEqual(
            {
                '_': utils.NETCONF_NAMESPACE,
                'nm': 's'
            }, xmlns
        )

    def test_xml_to_dict_turing(self):
        """example from turing machine"""
        xml = """
            <rpc xmlns:turing="http://example.net/turing-machine"
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                message-id="some_id">
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
        """
        xmlns = {
            utils.DEFAULT_NCNS: utils.NETCONF_NAMESPACE,
            # require for regen namespace
            self.FAKE_NS: "a"
        }
        result = {}
        utils.generate_dict_node(result, etree.XML(xml), xmlns)
        # check dict
        self.assertEqual(self.TURING_DICT, result)
        # check xmlns
        self.assertEqual(
            {
                self.FAKE_NS: 'a',
                self.REAL_NS: 'http://example.net/turing-machine',
                utils.DEFAULT_NCNS: utils.NETCONF_NAMESPACE
            }, xmlns
        )

    def test_dict_to_xml(self):
        """test minimal dict struct with tag list and attibutes"""
        xmlns = {
            '_': utils.NETCONF_NAMESPACE,
            'nm': 's'
        }

        xml_node = utils.generate_xml_node(
            self.SIMPLE_DICT,
            xmlns,
            'rpc'
        )

        xml_node_string = etree.tostring(
            xml_node, pretty_print=False
        )

        self.assertEqual(
            xml_node_string,
            """<rpc xmlns:nm="s" xmlns="urn:ietf:params:xml:ns:netc""" +
            """onf:base:1.0"><a xmlns:ns0="urn:ietf:params:xml:ns:n""" +
            """etconf:base:1.0"><c nm:nm="update"><d>1</d><d>2</d><""" +
            """d>3</d></c><b ns0:m="g">b</b></a></rpc>"""
        )

    def test_dict_to_xml_turing(self):
        """test turing dict struct with tag list and attibutes"""
        xmlns = {
            self.FAKE_NS: 'a',
            self.REAL_NS: 'http://example.net/turing-machine',
            utils.DEFAULT_NCNS: utils.NETCONF_NAMESPACE
        }

        xml_node = utils.generate_xml_node(
            self.TURING_DICT,
            xmlns,
            'rpc'
        )

        xml_node_string = etree.tostring(
            xml_node, pretty_print=False
        )

        self.assertEqual(xml_node_string, self.TURING_STRIPPED)

    def test_rpc_gen(self):
        """check rpc_gen"""
        xmlns = {
            'r': utils.NETCONF_NAMESPACE,
            'n': "someaction"
        }
        netconf_namespace, xmlns = utils.update_xmlns(
            xmlns
        )
        self.assertEqual(netconf_namespace, "r")
        data = {
            "b": "b"
        }
        # dont have namespace in action
        parent = utils.rpc_gen(
            "some_id", 'run', netconf_namespace, data, xmlns
        )
        rpc_string = etree.tostring(parent)
        example_string = (
            """<r:rpc xmlns:r="urn:ietf:params:xml:ns:netconf:base:""" +
            """1.0" xmlns:n="someaction" r:message-id="some_id"><r:""" +
            """run><r:b>b</r:b></r:run></r:rpc>"""
        )
        self.assertEqual(rpc_string, example_string)
        # have namespace in action
        parent = utils.rpc_gen(
            "some_id", 'n@run', netconf_namespace, data, xmlns
        )
        rpc_string = etree.tostring(parent)
        example_string = (
            """<r:rpc xmlns:r="urn:ietf:params:xml:ns:netconf:base:""" +
            """1.0" xmlns:n="someaction" r:message-id="some_id"><n:""" +
            """run><n:b>b</n:b></n:run></r:rpc>"""
        )
        self.assertEqual(rpc_string, example_string)

    def test_node_name(self):
        """check exceptions in node_name convertion"""
        xmlns = {
            "a": "_a",
            "g": "_g"
        }
        self.assertEqual(
            utils._node_name("a", "g", xmlns),
            (False, "g", "{_g}a")
        )
        self.assertEqual(
            utils._node_name("a@a", "g", xmlns),
            (False, "a", "{_a}a")
        )
        self.assertEqual(
            utils._node_name("_@@a", "g", xmlns),
            (True, "g", "{_g}a")
        )
        self.assertEqual(
            utils._node_name("_@a@a", "g", xmlns),
            (True, "a", "{_a}a")
        )
        # something not equal to _
        with self.assertRaises(cfy_exc.NonRecoverableError):
            utils._node_name("1@a@a", "g", xmlns),
        # too many @
        with self.assertRaises(cfy_exc.NonRecoverableError):
            utils._node_name("@@a@a", "g", xmlns),

    def test_update_xmlns(self):
        """check add default namespace"""
        namespace, xmlns = utils.update_xmlns({})
        self.assertEqual(
            namespace, utils.DEFAULT_NCNS
        )
        self.assertEqual(
            xmlns, {
                utils.DEFAULT_NCNS: utils.NETCONF_NAMESPACE
            }
        )

    def test_generate_xml_node(self):
        """can't generate enything without namspaces"""
        with self.assertRaises(cfy_exc.NonRecoverableError):
            utils.generate_xml_node({}, {}, "sometag")

    def test_default_xmlns(self):
        """check return wellknow namespaces"""
        self.assertTrue(utils.default_xmlns())

    def test_load_xml(self):
        """check code used for merge nodes"""
        original = "<a>a</a>"
        fake_file = mock.mock_open(read_data="<a>a</a>")
        with mock.patch(
            '__builtin__.open', fake_file
        ):
            xml = utils.load_xml("a.a")
            self.assertEqual(etree.tostring(xml), original)

    RELAXNG_MAIN = """
        <grammar
            xmlns:tm="http://example.net/turing-machine"
            xmlns="http://relaxng.org/ns/structure/1.0"
            xmlns:nma="urn:ietf:params:xml:ns:netmod:dsdl-annotations:1"
            datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes"
            ns="urn:ietf:params:xml:ns:netconf:base:1.0"
        >
            <include href="relaxng-lib.rng"/>
            <start>
                <element name="config">
                </element>
            </start>
        </grammar>
    """
    RELAXNG_SLAVE = """
        <grammar
            xmlns:tm="http://example.net/turing-machine"
            xmlns="http://relaxng.org/ns/structure/1.0"
            xmlns:nma="urn:ietf:params:xml:ns:netmod:dsdl-annotations:1"
            xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"
            xmlns:en="urn:ietf:params:xml:ns:netconf:notification:1.0"
            datatypeLibrary="http://www.w3.org/2001/XMLSchema-datatypes"
        >
            <define name="ok-element">
                <element name="nc:ok">
                    <empty/>
                </element>
            </define>
            <define name="turing-machine__state-index">
                <data type="unsignedShort"/>
            </define>
            <define name="turing-machine__head-dir">
                <choice>
                    <value>left</value>
                    <value>right</value>
                </choice>
            </define>
            <define name="turing-machine__tape-symbol">
                <data type="string">
                    <param name="minLength">0</param>
                    <param name="maxLength">1</param>
                </data>
            </define>
        </grammar>
    """
    RELAXNG_RESULT = (
        """<grammar xmlns:tm="http://example.net/turing-machine" xm""" +
        """lns="http://relaxng.org/ns/structure/1.0" xmlns:nma="urn""" +
        """:ietf:params:xml:ns:netmod:dsdl-annotations:1" datatypeL""" +
        """ibrary="http://www.w3.org/2001/XMLSchema-datatypes" ns""" +
        """="urn:ietf:params:xml:ns:netconf:base:1.0">\n           """ +
        """ <start>\n                <element name="config">\n     """ +
        """           </element>\n            </start>\n        <de""" +
        """fine xmlns:en="urn:ietf:params:xml:ns:netconf:notificati""" +
        """on:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.""" +
        """0" name="ok-element">\n                <element name="nc""" +
        """:ok">\n                    <empty/></element></define><d""" +
        """efine xmlns:en="urn:ietf:params:xml:ns:netconf:notificat""" +
        """ion:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1""" +
        """.0" name="turing-machine__state-index">\n               """ +
        """ <data type="unsignedShort"/></define><define xmlns:""" +
        """en="urn:ietf:params:xml:ns:netconf:notification:1.0" xml""" +
        """ns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" name="tu""" +
        """ring-machine__head-dir">\n                <choice>\n    """ +
        """                <value>left</value><value>right</value><""" +
        """/choice></define><define xmlns:en="urn:ietf:params:xml:n""" +
        """s:netconf:notification:1.0" xmlns:nc="urn:ietf:params:xm""" +
        """l:ns:netconf:base:1.0" name="turing-machine__tape-symbol""" +
        """">\n                <data type="string">\n              """ +
        """      <param name="minLength">0</param><param name="maxL""" +
        """ength">1</param></data></define></grammar>"""
    )

    def test_load_relaxng_includes(self):
        """check update relaxng with include"""
        xmlns = utils.default_xmlns()
        main_node = etree.XML(self.RELAXNG_MAIN)
        fake_file = mock.mock_open(read_data=self.RELAXNG_SLAVE)
        with mock.patch(
            '__builtin__.open', fake_file
        ):
            utils.load_relaxng_includes(main_node, xmlns)
        self.assertEqual(
            etree.tostring(main_node),
            self.RELAXNG_RESULT
        )

    def test_load_relaxng_includes_without_file(self):
        """check update relaxng with include"""
        xmlns = utils.default_xmlns()
        main_node = etree.XML(self.RELAXNG_MAIN)
        utils.load_relaxng_includes(
            main_node, xmlns, {
                "relaxng-lib.rng": etree.XML(self.RELAXNG_SLAVE)
            }
        )
        self.assertEqual(
            etree.tostring(main_node),
            self.RELAXNG_RESULT
        )

    def test_xml_validate(self):
        """check run xml validate"""
        relaxng_mock = mock.MagicMock()
        schematron_mock = mock.MagicMock()

        xmlns = {
            'r': utils.NETCONF_NAMESPACE,
            'n': "someaction"
        }

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
                parent = etree.XML("<a><b>c</b></a>")
                relaxng_mock.validate = mock.MagicMock(
                    return_value=False
                )
                schematron_mock.validate = mock.MagicMock(
                    return_value=False
                )
                # we dont have validation and nodes for it
                utils.xml_validate(parent, xmlns, "/d")

                # we have validation nodes and failed relaxng check
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    utils.xml_validate(parent, xmlns, "/a", "<d>a</d>")

                # we have validation nodes and failed shematron check
                with self.assertRaises(cfy_exc.NonRecoverableError):
                    utils.xml_validate(
                        parent, xmlns, "/a", None, "<d>a</d>"
                    )

                # everything fine
                relaxng_mock.validate = mock.MagicMock(
                    return_value=True
                )
                schematron_mock.validate = mock.MagicMock(
                    return_value=True
                )
                utils.xml_validate(
                    parent, xmlns, "/a", "<d>a</d>", "<d>a</d>"
                )

if __name__ == '__main__':
    unittest.main()
