#! /usr/bin/env python
"""
cenvars command line script
"""
import argparse
from . import api

def cenvars():
    """
    Fetch environmental variables from a Cenvars Server.
    """
    parser = argparse.ArgumentParser(description=cenvars.__doc__)
    parser.add_argument(
        '-k', '--key',
        help='The actual value of the encoded key')

    parser.add_argument(
        '-s', '--server',
        help='The full URL path of the server.')

    parser.add_argument(
        '-e', '--environment_name',
        help=('The environment name which (if) the encoded_key is stored under'
              ', by default "%s".') % api.constants.ENVIRONMENT_KEY_NAME)

    args = parser.parse_args()
    tmp = {'encoded_key':args.key,
           'url':args.server,
           'key_env_name':args.environment_name,
           'print_function':print}

    api.get(**tmp)


def cenvars_newkey():
    """
    Create a new Cenvars key.
    """
    parser = argparse.ArgumentParser(description=cenvars_newkey.__doc__)
    parser.add_argument(
        '-s', '--server',
        help='The full URL path of the cenvars server')

    parser.add_argument(
        '-k', '--key_size', type=int,
        default=api.constants.RSA_KEYSIZE,
        help='The actual value of the encoded key')

    parser.add_argument(
        '-e', '--environment_name',
        help=('The environment name which (if) the server URL is stored under'
              ', by default "%s".') % api.constants.ENVIRONMENT_KEY_NAME)

    args = parser.parse_args()
    tmp = {'url':args.server,
           'key_size':args.key_size,
           'url_env_name':args.environment_name,
           'print_function':print}

    api.create_key(**tmp)
