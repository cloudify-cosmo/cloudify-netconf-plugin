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
import paramiko
from StringIO import StringIO


class connection(object):

    # final of any package
    MAGIC_END = "]]>]]>"

    # ssh connection
    ssh = None
    chan = None

    # buffer for same packages, will save partial packages between calls
    buff = ""

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
        """send xml string by link"""
        self.chan.send(xml + self.MAGIC_END)
        while self.buff.find(self.MAGIC_END) == -1:
            self.buff += self.chan.recv(8192)
        package_end = self.buff.find(self.MAGIC_END)
        response = self.buff[:package_end]
        self.buff = self.buff[package_end + len(self.MAGIC_END):]
        return response

    def close(self, goodbye_string):
        """send xml string by link and close connection"""
        response = self.send(goodbye_string)
        self.chan.close()
        self.ssh.close()
        return response
