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
import paramiko
from StringIO import StringIO

# final of any package
NETCONF_1_0_END = "]]>]]>"
# base level of communication
NETCONF_1_0_CAPABILITY = 'urn:ietf:params:netconf:base:1.0'
# package based communication
NETCONF_1_1_CAPABILITY = 'urn:ietf:params:netconf:base:1.1'


class connection(object):

    # ssh connection
    ssh = None
    chan = None

    # buffer for same packages, will save partial packages between calls
    buff = ""

    current_level = NETCONF_1_0_CAPABILITY

    def connect(
        self, ip, user, hello_string, password=None, key_content=None
    ):
        """open connection and send xml string by link"""
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_content:
            key = paramiko.RSAKey.from_private_key(
                StringIO(key_content)
            )
            self.ssh.connect(
                ip, username=user, pkey=key, port=830
            )
        else:
            self.ssh.connect(
                ip, username=user, password=password, port=830
            )
        self.chan = self.ssh.get_transport().open_session()
        self.chan.invoke_subsystem('netconf')
        self.buff = ""
        capabilities = self.send(hello_string)
        return capabilities

    def send(self, xml):
        """send xml string by connection"""
        if self.current_level == NETCONF_1_1_CAPABILITY:
            return self._send_1_1(xml)
        else:
            return self._send_1_0(xml)

    def _send_1_0(self, xml):
        """send xml string with NETCONF_1_0_END by connection"""
        if xml:
            self.chan.send(xml + NETCONF_1_0_END)
        while self.buff.find(NETCONF_1_0_END) == -1:
            self.buff += self.chan.recv(8192)
        package_end = self.buff.find(NETCONF_1_0_END)
        response = self.buff[:package_end]
        self.buff = self.buff[package_end + len(NETCONF_1_0_END):]
        return response

    def _send_1_1(self, xml):
        """send xml string as package by connection"""
        if xml:
            message = "\n#" + str(len(xml)) + "\n"
            message += xml
            message += "\n##\n"
            self.chan.send(message)
        get_everything = False
        response = ""
        while not get_everything:
            if len(self.buff) < 2:
                self.buff += self.chan.recv(2)
            # skip new line
            if self.buff[:2] != "\n#":
                raise cfy_exc.NonRecoverableError("no start")
            self.buff = self.buff[2:]
            # get package length
            while self.buff.find("\n") == -1:
                self.buff += self.chan.recv(20)
            if self.buff[:2] == "#\n":
                get_everything = True
                self.buff = self.buff[2:]
                break
            length = int(self.buff[:self.buff.find("\n")])
            self.buff = self.buff[self.buff.find("\n") + 1:]
            # load current package
            while length > len(self.buff):
                self.buff += self.chan.recv(length - len(self.buff))
            response += self.buff[:length]
            self.buff = self.buff[length:]
        return response

    def close(self, goodbye_string):
        """send xml string by link and close connection"""
        response = self.send(goodbye_string)
        self.chan.close()
        self.ssh.close()
        return response
