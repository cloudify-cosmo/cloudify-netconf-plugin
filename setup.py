#!/usr/bin/env python

from distutils.core import setup

setup(
    name='cloudify-netconf-plugin',
    version='0.1',
    description='support netconf',
    author='Denis Pauk',
    author_email='pauk.denis@gmail.com',
    license='LICENSE',
    packages=['cloudify_netconf'],
    scripts=['tools/yaml2netconfxml.py', 'tools/netconfxml2yaml.py'],
    install_requires=[
        'cloudify-plugins-common>=3.3',
    ]
)
