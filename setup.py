"""
PyPi Setup file.
"""
import os
# pylint: disable=no-name-in-module, import-error
from setuptools import setup

NAME = 'cenvars-client'
DESCRIPTION = 'A Cenvars client and api library.'
VERSION = '0.0.1.3'
LICENSE = 'BSD'
AUTHOR = 'Martin P. Hellwig'
AUTHOR_EMAIL = 'martin.hellwig@gmail.com'
#
URL_MAIN = "https://bitbucket.org/hellwig/" + NAME + '/'
DOWNLOAD_ID = os.environ.get('CI_COMMIT_ID', VERSION)
URL_DOWNLOAD = URL_MAIN + 'get/' + DOWNLOAD_ID + '.zip'
#
PACKAGES = ['cenvars']
PACKAGE_DATA  = {}
SCRIPTS = ['cenvars=cenvars.cli:cenvars',
           'cenvars_newkey=cenvars.cli:cenvars_newkey']
KEYWORDS = [
    'cenvars',
    ]
CLASSIFIERS = [
    'Programming Language :: Python :: 3',
    ]
REQUIREMENTS = [
    'pip',
    'rsa',
    'pyaes',
    'requests',
    ]


################################################################################

KWARGS = {
    'name':NAME, 'packages':PACKAGES, 'version':VERSION,
    'description':DESCRIPTION, 'author':AUTHOR, 'author_email':AUTHOR_EMAIL,
    'url':URL_MAIN, 'download_url':URL_DOWNLOAD, 'keywords':KEYWORDS,
    'license':LICENSE, 'classifiers':CLASSIFIERS,
    'install_requires':REQUIREMENTS, 'package_data':PACKAGE_DATA,
    'entry_points':{'console_scripts':SCRIPTS},}

setup(**KWARGS)
