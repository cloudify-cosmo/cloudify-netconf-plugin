#!/usr/bin/env python

from distutils.core import setup

setup(
    name='cloudify-netconf-tools',
    version='0.1',
    description='tools for netconf',
    author='Denis Pauk',
    author_email='pauk.denis@gmail.com',
    license='LICENSE',
    scripts=['scripts/yaml2netconfxml.py', 'scripts/netconfxml2yaml.py'],
    install_requires=[
        'cloudify-netconf-plugin',
        'lxml',
        'pyaml',
    ]
)
