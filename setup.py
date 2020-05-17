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
from setuptools import setup

setup(
    name='cloudify-netconf-plugin',
    version='0.4.2',
    description='Cloudify Netconf plugin',
    author='Cloudify Platform Ltd.',
    author_email='hello@cloudify.co',
    license='LICENSE',
    packages=['cloudify_netconf'],
    install_requires=[
        'cloudify-common==5.1.0.dev1',
        'lxml',
        'requests', # url templates
        'cloudify-utilities-plugins-sdk>=0.0.10',  # ssh connection
        'xmltodict', # convert xml to dict
    ]
)
