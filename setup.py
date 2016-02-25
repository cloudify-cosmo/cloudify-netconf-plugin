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
from distutils.core import setup

setup(
    name='cloudify-netconf-plugin',
    version='0.1',
    description='support netconf',
    author='Denis Pauk',
    author_email='pauk.denis@gmail.com',
    license='LICENSE',
    packages=['cloudify_netconf'],
    install_requires=[
        'cloudify-plugins-common>=3.3',
        'lxml',
        'paramiko',  # for ssh netconf connection
    ],
    data_files=[
        ('share/netconf/xslt', [
            'share-files/xslt/gen-common.xsl',
            'share-files/xslt/gen-relaxng.xsl',
            'share-files/xslt/gen-schematron.xsl',
        ]),
        ('share/netconf/schema', [
            'share-files/schema/edit-config-attributes.rng',
            'share-files/schema/relaxng-lib.rng',
        ]),
    ]
)
