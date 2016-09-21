"""
Defined constants
"""

RSA_KEYSIZE = 2048
ENVIRONMENT_KEY_NAME = 'CENVARS_KEY'
ENVIRONMENT_URL_NAME = 'CENVARS_URL'
GET_RETRIES = 3

# pylint: disable=missing-docstring, multiple-statements
class CenvarsError(ValueError): pass
class CenvarsEnvironmentError(CenvarsError): pass
