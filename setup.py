#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='aioenocean',
    version='0.0.1',
    description='Asyncio EnOcean serial protocol implementation',
    author='ChristopheHD',
    author_email='',
    url='https://github.com/ChristopheHD/aioenocean',
    packages=[
        'enocean',
        'enocean.protocol',
        'enocean.communicators',
    ],
    scripts=[
        'examples/enocean_example.py',
    ],
    package_data={
        '': ['EEP.xml']
    },
    install_requires=[
        'enum-compat>=0.0.2',
        'pyserial>=3.0',
        'beautifulsoup4>=4.3.2',
    ])
