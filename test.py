# Copyright (c) 2016, Martin P. Hellwig, All Rights Reserved.
"""
Unit Test module
"""
import os
import unittest
from rsa.pkcs1 import DecryptionError
from cenvars import api, cli

class TestAPI(unittest.TestCase):
    "Generic Testing of the API"
    def test_010_smoke(self, key_size=512):
        "This should cover most code"
        url = 'http://example.com/cenvars'
        encoded_key = api.create_key(url, key_size,
                                     print_function=lambda text: None)
        r_url, key_size, identity, rsa_key = api.decode_key(encoded_key)
        self.assertTrue(len(identity))
        self.assertEqual(url, r_url)
        test_data = {'some_key':'some_value'}
        encrypted = api.encrypt(rsa_key, test_data)
        decrypted = api.decrypt(rsa_key, encrypted, key_size)
        self.assertEqual(test_data, decrypted)
        return encoded_key, encrypted, test_data

    def test_020_get(self):
        "Testing the api.get"
        encoded_key, encrypted, test_data = self.test_010_smoke()

        import requests
        def raise_for_status(argument):
            "Mock function for mock"
            assert argument

        mock_content = {'content':encrypted,
                        'raise_for_status':raise_for_status}

        def mock(*args, **kwargs):
            "Mocking requests.get"
            mock_content['args'] = args
            mock_content['kwargs'] = kwargs
            return type('mock', (object,), mock_content)()

        restore = requests.get
        requests.get = mock

        data = api.get(encoded_key, print_function=lambda text: None)
        self.assertEqual(test_data, data)

        # test content is damaged during transit
        mock_content['content'] = encrypted[-5:] + encrypted[:-5]
        self.assertRaises(DecryptionError, api.get, encoded_key)
        mock_content['content'] = encrypted

        # test environment_key is broken
        broken_key = encoded_key[::-1]
        self.assertRaises(api.constants.CenvarsEnvironmentError,
                          api.get, broken_key)
        requests.get = restore

    def test_030_create_key_error(self):
        "Does it raises an error when no url is specified?"
        self.assertRaises(api.constants.CenvarsEnvironmentError,
                          api.create_key, key_size=512)


    def test_040_get_error(self):
        "Does it raises an error when no key is specified?"
        if api.constants.ENVIRONMENT_KEY_NAME in os.environ:
            os.environ.pop(api.constants.ENVIRONMENT_KEY_NAME)
        self.assertRaises(api.constants.CenvarsEnvironmentError, api.get)

    def test_050_cli(self):
        "Does it raise and appropriate error"
        if api.constants.ENVIRONMENT_KEY_NAME in os.environ:
            os.environ.pop(api.constants.ENVIRONMENT_KEY_NAME)
        exception = api.constants.CenvarsEnvironmentError
        self.assertRaises(exception, cli.cenvars)
        self.assertRaises(exception, cli.cenvars_newkey)



if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
