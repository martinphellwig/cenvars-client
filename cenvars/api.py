"""
The API for cenvars.
"""
import os as _os
from rsa.pkcs1 import DecryptionError as _DecryptionError
import requests as _requests
from . import constants
from .codec import encode_key, decode_key, decrypt, rsa
from .codec import encrypt #pylint:disable=unused-import

def get(encoded_key=None, url=None, key_env_name=None, print_function=False):
    "Fetch the environmental data."
    if key_env_name is None:
        key_env_name = constants.ENVIRONMENT_KEY_NAME

    if encoded_key is None:
        encoded_key = _os.environ.get(key_env_name)

    if encoded_key is None:
        text = ("Either supply cenvars key via key parameter or set the "
                "environment variable %s to the appropriate value.")
        raise constants.CenvarsEnvironmentError(text % key_env_name)

    try:
        decoded = decode_key(encoded_key)
    except:
        text = 'Cenvars key is corrupt, renewal required.'
        raise constants.CenvarsEnvironmentError(text)

    if url is None:
        url = decoded[0]

    if not url.endswith('/'):
        url += '/'

    key_size, identity, rsa_key = decoded[1:]

    tries = constants.GET_RETRIES
    while tries > 0:
        tries -= 1
        try:
            got = _requests.get(url+identity)
            got.raise_for_status()
            data = decrypt(rsa_key, got.content, key_size)
        except _DecryptionError:
            if tries == 0:
                raise

    if print_function:
        for key, value in data.items():
            print_function("export %s='%s'" % (key, value))

    return data


def create_key(url=None, key_size=constants.RSA_KEYSIZE, url_env_name=None,
               print_function=False):
    "Create a new key."
    if url_env_name is None:
        url_env_name = constants.ENVIRONMENT_URL_NAME

    if url is None:
        url = _os.environ.get(url_env_name)

    if url is None:
        text = ("Either supply url via key parameter or set the environment "
                "variable %s to the appropriate url value.")
        raise constants.CenvarsEnvironmentError(text % url_env_name)

    _, key = rsa.newkeys(key_size)
    _, tmp = encode_key(key, url=url, key_size=key_size)

    if print_function:
        print_function(tmp)
    return tmp
