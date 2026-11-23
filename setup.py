#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='enocean',
    version='1.0.0',
    description='EnOcean serial protocol implementation',
    long_description='A Python library for reading and controlling EnOcean devices.',
    author='Kimmo Huoman',
    author_email='kipenroskaposti@gmail.com',
    maintainer='Christophe Hardouin Duparc',
    maintainer_email='christophe.hardouin.duparc@gmail.com',
    url='https://github.com/ChristopheHD/enocean',
    classifiers = [
        'License :: OSI Approved :: MIT License',
    ],
    packages=[
        'enocean',
        'enocean.protocol',
        'enocean.communicators',
    ],
    scripts=[
        'examples/enocean_example.py',
    ],
    package_data={
        'enocean.protocol': ['EEP.xml']
    },
    include_package_data=True,
    install_requires=[
        'pyserial>=3.5',
        'cryptography>=3.1',
    ])
