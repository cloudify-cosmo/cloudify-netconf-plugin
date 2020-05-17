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
from lxml import etree
from collections import OrderedDict
import unittest
import xmltodict
import json

from cloudify import exceptions as cfy_exc
import cloudify_netconf.utils as utils


class UtilsMockTest(unittest.TestCase):

    UNSORTED_DICT = {
        'a': {
            'b': {
                'c': 'd'
            }
        }
    }

    SIMPLE_DICT = OrderedDict([
        ('a', OrderedDict([
            ('b', OrderedDict([
                ('_@@', 'b'),
                ('_@@m', 'g')
            ])),
            ('c', OrderedDict([
                ('f', '1'),
                ('e', 'str'),
                ('d', ['1', '2', '3']),
                ('_@nm@nm', 'update')
            ]))
        ]))
    ])

    # unexisted namespace, but it will block usage of such name in tests
    FAKE_NS = "turing"
    # and new name will be
    REAL_NS = "_turing_"

    TURING_DICT = OrderedDict([
        ('rfc6020@rpc', OrderedDict([
            ('rfc6020@get', OrderedDict([
                ('rfc6020@filter', OrderedDict([
                    (REAL_NS + '@turing-machine', OrderedDict([
                        (REAL_NS + '@transition-function', None)
                    ])),
                    ('_@rfc6020@type', 'subtree')
                ])),
                ('rfc6020@source', OrderedDict([
                    ('rfc6020@running', None)
                ]))
            ])),
            ('_@rfc6020@message-id', 'some_id')
        ]))
    ])

    # stripped version of turing xml
    TURING_STRIPPED = (
        """<rfc6020:rpc xmlns:_turing_="http://example.net/turing-m""" +
        """achine" xmlns:rfc6020="urn:ietf:params:xml:ns:netconf:ba""" +
        """se:1.0" xmlns:turing="a" rfc6020:message-id""" +
        """="some_id"><rfc6020:get><rfc6020:filter rfc6020:type="su""" +
        """btree"><_turing_:turing-machine><_turing_:transition-fun""" +
        """ction/></_turing_:turing-machine></rfc6020:filter><rfc60""" +
        """20:source><rfc6020:running/></rfc6020:source></rfc6020:g""" +
        """et></rfc6020:rpc>"""
    )

    def test_xml_to_dict_net_namespace(self):
        """test create new namespace shortname"""
        xml = """
            <a
                xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
            >
                <b xmlns="something">b</b>
                <!-- Comment, ignore it -->
            </a>
        """
        xmlns = {
            "_": utils.NETCONF_NAMESPACE
        }
        result = utils.generate_dict_node(etree.XML(xml), xmlns)
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
                    <f>1</f>
                    <e>str</e>
                    <d>1</d>
                    <d>2</d>
                    <d>3</d>
                </c>
            </a>
        """
        xmlns = {
            "_": utils.NETCONF_NAMESPACE
        }
        result = utils.generate_dict_node(etree.XML(xml), xmlns)
        # check dict
        self.assertDictEqual(
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
        xmlns = {
            utils.DEFAULT_NCNS: utils.NETCONF_NAMESPACE,
            # require for regen namespace
            self.FAKE_NS: "a"
        }
        result = utils.generate_dict_node(etree.XML(self.TURING_STRIPPED),
                                          xmlns)
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

    def test_dict_unsorted(self):
        """test simple dictionary that can be unsorted"""
        xmlns = {
            '_': utils.NETCONF_NAMESPACE,
            'nm': 's'
        }

        xml_node = utils.generate_xml_node(
            self.UNSORTED_DICT,
            xmlns,
            'rpc'
        )

        xml_node_string = etree.tostring(
            xml_node, pretty_print=False
        )

        self.assertEqual(
            json.dumps(xmltodict.parse(xml_node_string.decode('utf-8')),
                       indent=4, sort_keys=True),
            json.dumps(xmltodict.parse("""<rpc xmlns:nm="s" xmlns="urn""" +
                                       """:ietf:params:xml:ns:netconf""" +
                                       """:base:1.0"><a>""" +
                                       """<b><c>d</c></b></a></rpc>"""),
                       indent=4, sort_keys=True)
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
            json.dumps(xmltodict.parse(xml_node_string.decode('utf-8')),
                       indent=4, sort_keys=True),
            json.dumps(xmltodict.parse(
                """<rpc xmlns:nm="s" xmlns="urn:ietf:params:xml:ns:netc""" +
                """onf:base:1.0"><a xmlns:ns0="urn:ietf:params:xml:ns:n""" +
                """etconf:base:1.0"><b ns0:m="g">b</b><c nm:nm="update">""" +
                """<f>1</f><e>str</e><d>1</d><d>2</d><d>3</d></c></a>""" +
                """</rpc>"""), indent=4, sort_keys=True)
        )

    def test_dict_to_xml_raw_include(self):
        """test minimal dict with raw insert values"""
        xmlns = {
            '_': utils.NETCONF_NAMESPACE
        }

        xml_node = utils.generate_xml_node(
            {
                'a': {
                    '_!_': "<g><a n='1'></a><d n='2'></d><c n='3'></c></g>"
                }
            },
            xmlns,
            'rpc'
        )

        xml_node_string = etree.tostring(
            xml_node, pretty_print=False
        )

        self.assertEqual(
            xml_node_string.decode('utf-8'),
            """<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:""" +
            """1.0"><a><g><a n="1"/><d n="2"/><c n="3"/></g></a></rpc>"""
        )

    def test_dict_to_xml_turing(self):
        """test turing dict struct with tag list and attibutes"""
        xmlns = {
            self.FAKE_NS: 'a',
            self.REAL_NS: 'http://example.net/turing-machine',
            utils.DEFAULT_NCNS: utils.NETCONF_NAMESPACE
        }

        xml_node = utils.generate_xml_node(
            # we should use subelement because parent will be rpc
            self.TURING_DICT['rfc6020@rpc'],
            xmlns,
            # parent name
            'rpc'
        )

        xml_node_string = etree.tostring(
            xml_node, pretty_print=False
        )

        self.assertEqual(
            json.dumps(xmltodict.parse(xml_node_string.decode('utf-8')),
                       indent=4, sort_keys=True),
            json.dumps(xmltodict.parse(self.TURING_STRIPPED),
                       indent=4, sort_keys=True)
        )

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
            """<r:rpc xmlns:n="someaction" xmlns:r="urn:ietf:""" +
            """params:xml:ns:netconf:base:1.0" r:message-id""" +
            """="some_id"><r:run><r:b>b</r:b></r:run></r:rpc>"""
        )
        self.assertEqual(
            json.dumps(xmltodict.parse(rpc_string.decode('utf-8')),
                       indent=4, sort_keys=True),
            json.dumps(xmltodict.parse(example_string),
                       indent=4, sort_keys=True)
        )
        # have namespace in action
        parent = utils.rpc_gen(
            "some_id", 'n@run', netconf_namespace, data, xmlns
        )
        rpc_string = etree.tostring(parent)
        example_string = (
            """<r:rpc xmlns:n="someaction" xmlns:r="urn:ietf:""" +
            """params:xml:ns:netconf:base:1.0" r:message-id""" +
            """="some_id"><n:run><n:b>b</n:b></n:run></r:rpc>"""
        )
        self.assertEqual(
            json.dumps(xmltodict.parse(rpc_string.decode('utf-8')),
                       indent=4, sort_keys=True),
            json.dumps(xmltodict.parse(example_string),
                       indent=4, sort_keys=True)
        )

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

    def test_get_free_ns(self):
        """check free namespace search"""
        xmlns = {"a": "b"}
        self.assertEqual(utils._get_free_ns(xmlns, "abrac:adabra"),
                         "_abrac_adabra")
        self.assertEqual(xmlns, {"a": "b",
                                 "_abrac_adabra": "abrac:adabra"})
        # duplicate
        self.assertEqual(utils._get_free_ns(xmlns, "abrac/adabra"),
                         "__abrac_adabra_")
        self.assertEqual(xmlns, {"a": "b",
                                 "_abrac_adabra": "abrac:adabra",
                                 "__abrac_adabra_": "abrac/adabra"})


if __name__ == '__main__':
    unittest.main()
