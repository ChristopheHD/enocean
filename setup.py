#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import io
import os


here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as readme:
    README = readme.read()

setup(
    name='enocean',
    version='1.0.0',
    description='EnOcean serial protocol implementation',
    long_description=README,
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
