# Copyright (c) 2015-2018 Cloudify Platform Ltd. All rights reserved
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
import mock
import unittest

import cloudify_terminal_sdk.netconf_connection as netconf_connection
from cloudify_common_sdk import exceptions


class NetConfConnectionTest(unittest.TestCase):

    def generate_all_mocks(self):
        """will generate netconf obj with all need mocks"""
        netconf = netconf_connection.NetConfConnection()
        netconf.ssh = mock.Mock()
        netconf.ssh.close = mock.MagicMock()
        netconf.conn = mock.Mock()
        netconf.conn.close = mock.MagicMock()
        # 256 - send by 256 bytes
        netconf.conn.send = mock.MagicMock(return_value=256)
        netconf.conn.recv = mock.MagicMock(
            return_value=netconf_connection.NETCONF_1_0_END
        )
        netconf.conn.closed = True
        return netconf

    def test_send_1_0(self):
        """check send"""
        netconf = self.generate_all_mocks()
        netconf.conn.recv = mock.MagicMock(
            return_value=(
                "pong" + netconf_connection.NETCONF_1_0_END
            )
        )
        self.assertEqual(
            "pong",
            netconf.send("ping")
        )
        netconf.conn.send.assert_called_with(
            "ping" + netconf_connection.NETCONF_1_0_END
        )

    def test_send_1_0_close_without_final_part(self):
        """check send with fast close"""
        netconf = self.generate_all_mocks()
        netconf.conn.recv = mock.MagicMock(
            return_value=(
                "pong"
            )
        )
        self.assertEqual(
            "pong",
            netconf.send("ping")
        )
        netconf.conn.send.assert_called_with(
            "ping" + netconf_connection.NETCONF_1_0_END
        )

    def test_send_1_1(self):
        """check send with 1.1 version"""
        netconf = self.generate_all_mocks()
        netconf.current_level = netconf_connection.NETCONF_1_1_CAPABILITY
        netconf.conn.recv = mock.MagicMock(
            return_value=(
                "\n#5\n<rpc>\n#6\n</rpc>\n##\n"
            )
        )
        self.assertEqual(
            "<rpc></rpc>",
            netconf.send("ping")
        )
        netconf.conn.send.assert_called_with(
            "\n#4\nping\n##\n"
        )
        # check with preloaded
        netconf.buff = "\n#25\n12345678901234567890"
        netconf.conn.recv = mock.MagicMock(
            return_value=(
                "12345\n#5\n<rpc>\n#6\n</rpc>\n##\n"
            )
        )
        self.assertEqual(
            "1234567890123456789012345<rpc></rpc>",
            netconf.send("ping")
        )
        netconf.conn.send.assert_called_with(
            "\n#4\nping\n##\n"
        )
        self.assertEqual(
            "", netconf.buff
        )
        # check with preloaded
        netconf.buff = "\n#5"
        netconf.conn.recv = mock.MagicMock(
            return_value=(
                "\n12345\n#5\n<rpc>\n#6\n</rpc>\n##\n"
            )
        )
        self.assertEqual(
            "12345<rpc></rpc>",
            netconf.send("ping")
        )
        netconf.conn.send.assert_called_with(
            "\n#4\nping\n##\n"
        )
        self.assertEqual(
            "", netconf.buff
        )
        # broken package
        netconf.conn.recv = mock.MagicMock(
            return_value=(
                "\n1"
            )
        )
        with self.assertRaises(exceptions.NonRecoverableError):
            netconf.send("ping")
        # empty package with closed connection
        netconf.buff = ""
        netconf.conn.recv = mock.MagicMock(return_value=(""))
        self.assertEqual(netconf.send("ping"), "")

    def test_close(self):
        netconf = self.generate_all_mocks()
        netconf.conn.recv = mock.MagicMock(
            return_value=(
                "ok" + netconf_connection.NETCONF_1_0_END
            )
        )
        self.assertEqual(
            "ok",
            netconf.close("close")
        )
        netconf.conn.send.assert_called_with(
            "close" + netconf_connection.NETCONF_1_0_END
        )
        netconf.conn.close.assert_called_with()
        netconf.ssh.close.assert_called_with()

    def test_connect_with_password(self):
        """connect call with password"""
        # ssh mock
        will_be_ssh = mock.Mock()
        will_be_ssh.connect = mock.MagicMock()
        # channel mock
        channel_mock = mock.Mock()
        channel_mock.recv = mock.MagicMock(
            return_value=(
                "ok" + netconf_connection.NETCONF_1_0_END
            )
        )
        channel_mock.send = mock.MagicMock()
        channel_mock.invoke_subsystem = mock.MagicMock()
        # transport mock
        transport_mock = mock.MagicMock()
        transport_mock.open_session = mock.MagicMock(
            return_value=channel_mock
        )
        will_be_ssh.get_transport = mock.MagicMock(
            return_value=transport_mock
        )
        mock_ssh_client = mock.MagicMock(return_value=will_be_ssh)
        with mock.patch("paramiko.SSHClient", mock_ssh_client):
            netconf = netconf_connection.NetConfConnection()
            message = netconf.connect(
                "127.0.0.100", "me", hello_string="hi",
                password="unknow"
            )
        # check calls
        self.assertEqual(message, "ok")
        mock_ssh_client.assert_called_with()
        will_be_ssh.connect.assert_called_with(
            '127.0.0.100', username='me', password='unknow', port=830,
            allow_agent=False, look_for_keys=False, timeout=5
        )
        will_be_ssh.get_transport.assert_called_with()
        transport_mock.open_session.assert_called_with()
        channel_mock.invoke_subsystemassert_called_with('netconf')
        channel_mock.send.assert_called_with(
            "hi" + netconf_connection.NETCONF_1_0_END
        )

    def test_connect_with_key(self):
        """connect call with key"""
        # ssh mock
        will_be_ssh = mock.Mock()
        will_be_ssh.connect = mock.MagicMock()
        # channel mock
        channel_mock = mock.Mock()
        channel_mock.recv = mock.MagicMock(
            return_value=(
                "ok" + netconf_connection.NETCONF_1_0_END
            )
        )
        channel_mock.send = mock.MagicMock()
        channel_mock.invoke_subsystem = mock.MagicMock()
        # transport mock
        transport_mock = mock.MagicMock()
        transport_mock.open_session = mock.MagicMock(
            return_value=channel_mock
        )
        will_be_ssh.get_transport = mock.MagicMock(
            return_value=transport_mock
        )
        mock_ssh_client = mock.MagicMock(return_value=will_be_ssh)
        with mock.patch("paramiko.SSHClient", mock_ssh_client):
            with mock.patch(
                "paramiko.RSAKey.from_private_key",
                mock.MagicMock(return_value="secret")
            ):
                netconf = netconf_connection.NetConfConnection()
                message = netconf.connect(
                    "127.0.0.100", "me", hello_string="hi",
                    key_content="unknow"
                )
        # check calls
        self.assertEqual(message, "ok")
        mock_ssh_client.assert_called_with()
        will_be_ssh.connect.assert_called_with(
            '127.0.0.100', username='me', pkey='secret', port=830,
            allow_agent=False, timeout=5
        )
        will_be_ssh.get_transport.assert_called_with()
        transport_mock.open_session.assert_called_with()
        channel_mock.invoke_subsystemassert_called_with('netconf')
        channel_mock.send.assert_called_with(
            "hi" + netconf_connection.NETCONF_1_0_END
        )


if __name__ == '__main__':
    unittest.main()
