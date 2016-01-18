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
import cloudify_netconf.netconf_connection as netconf_connection
import mock
import paramiko
import unittest


class nwtConfConnectionMockTest(unittest.TestCase):

    def generate_all_mocks(self):
        """will generate netconf obj with all need mocks"""
        netconf = netconf_connection.connection()
        netconf.ssh = mock.Mock()
        netconf.ssh.close = mock.MagicMock()
        netconf.chan = mock.Mock()
        netconf.chan.close = mock.MagicMock()
        netconf.chan.send = mock.MagicMock()
        netconf.chan.recv = mock.MagicMock(
            return_value=netconf_connection.connection.MAGIC_END
        )
        return netconf

    def test_send(self):
        """check send"""
        netconf = self.generate_all_mocks()
        netconf.chan.recv = mock.MagicMock(
            return_value=(
                "pong" + netconf_connection.connection.MAGIC_END
            )
        )
        self.assertEqual(
            "pong",
            netconf.send("ping")
        )
        netconf.chan.send.assert_called_with(
            "ping" + netconf_connection.connection.MAGIC_END
        )

    def test_close(self):
        netconf = self.generate_all_mocks()
        netconf.chan.recv = mock.MagicMock(
            return_value=(
                "ok" + netconf_connection.connection.MAGIC_END
            )
        )
        self.assertEqual(
            "ok",
            netconf.close("close")
        )
        netconf.chan.send.assert_called_with(
            "close" + netconf_connection.connection.MAGIC_END
        )
        netconf.chan.close.assert_called_with()
        netconf.ssh.close.assert_called_with()

    def test_connect(self):
        """connect call"""
        # ssh mock
        will_be_ssh = mock.Mock()
        will_be_ssh.set_missing_host_key_policy = mock.MagicMock()
        will_be_ssh.connect = mock.MagicMock()
        # channel mock
        channel_mock = mock.Mock()
        channel_mock.recv = mock.MagicMock(
            return_value=(
                "ok" + netconf_connection.connection.MAGIC_END
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

        with mock.patch.object(
            paramiko, 'SSHClient', return_value=will_be_ssh
        ) as mock_ssh_client:
            with mock.patch.object(
                paramiko, 'AutoAddPolicy', return_value="I'm policy"
            ) as mock_policy:
                netconf = netconf_connection.connection()
                message = netconf.connect(
                    "127.0.0.100", "me", "unknow", "hi"
                )
        # check calls
        self.assertEqual(message, "ok")
        mock_ssh_client.assert_called_with()
        mock_policy.assert_called_with()
        will_be_ssh.set_missing_host_key_policy.assert_called_with(
            "I'm policy"
        )
        will_be_ssh.connect.assert_called_with(
            '127.0.0.100', username='me', password='unknow', port=830
        )
        will_be_ssh.get_transport.assert_called_with()
        transport_mock.open_session.assert_called_with()
        channel_mock.invoke_subsystemassert_called_with('netconf')
        channel_mock.send.assert_called_with(
            "hi" + netconf_connection.connection.MAGIC_END
        )

if __name__ == '__main__':
    unittest.main()
