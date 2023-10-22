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
import os
import re
import pathlib

from setuptools import setup


def get_version():
    current_dir = pathlib.Path(__file__).parent.resolve()
    with open(os.path.join(current_dir, 'cloudify_netconf/__version__.py'),
              'r') as outfile:
        var = outfile.read()
        return re.search(r'\d+.\d+.\d+', var).group()


setup(
    name='cloudify-netconf-plugin',
    version='0.4.12',
    description='Cloudify Netconf plugin',
    author='Cloudify Platform Ltd.',
    author_email='hello@cloudify.co',
    license='LICENSE',
    packages=['cloudify_netconf'],
    install_requires=[
        'cloudify-common>=4.6',
        'lxml',
        'requests', # url templates
        'cloudify-utilities-plugins-sdk>=0.0.26',  # ssh connection
        'xmltodict', # convert xml to dict
    ]
)
