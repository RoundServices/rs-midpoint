# rs-midpoint is available under the MIT License. https://github.com/roundservices/rs-midpoint/
# Copyright (c) 2023, Round Services LLC - https://roundservices.biz/
#
# Author: Gustavo J Gallardo - ggallard@roundservices.biz
#

from setuptools import setup

setup(
    name='rs-midpoint',
    version='1.1.0-20231016',
    description='Python utilities for Midpoint',
    url='git@github.com:RoundServices/rs-midpoint.git',
    author='Round Services LLC',
    author_email='info@roundservices.biz',
    license='MIT License',
    install_requires=['requests'],
    packages=['rs.midpoint'],
    zip_safe=False,
    python_requires='>=3.0'
)
