"""
Codecs used for keys, etc.
"""
import json
import zlib
import base64
import os
import hashlib
import rsa
import pyaes
from . import constants

def encrypt(rsa_key, data):
    "Encrypt/Encode data dictionary using json, utf8, zlib, aes and rsa."
    data_json = json.dumps(data)
    data_utf8 = data_json.encode('utf8')
    data_zlib = zlib.compress(data_utf8, 9)
    key_aes = os.urandom(32)
    aes = pyaes.AESModeOfOperationCTR(key_aes)
    data_aes = aes.encrypt(data_zlib)
    rsa_aes = rsa.encrypt(key_aes, rsa_key)
    returns = rsa_aes+data_aes
    return returns

def decrypt(rsa_key, encrypted, key_size=constants.RSA_KEYSIZE):
    "Decrypt/Decode to data dictionary using rsa, aes, zlib, utf8 and json."
    size = key_size // 8
    rsa_aes = encrypted[:size]
    encrypted = encrypted[size:]
    key_aes = rsa.decrypt(rsa_aes, rsa_key)
    aes = pyaes.AESModeOfOperationCTR(key_aes)
    data_aes = aes.decrypt(encrypted)
    data_zlib = zlib.decompress(data_aes)
    data_utf8 = data_zlib.decode('utf8')
    data = json.loads(data_utf8)
    return data

def _hash_rsa_n(key, key_size):
    "Hash the n part of the rsa key and return the hexdigest."
    n_bytes = key.n.to_bytes(key_size // 8, 'big')
    return hashlib.sha224(n_bytes).hexdigest().upper()

def encode_key(rsa_key, url, key_size=constants.RSA_KEYSIZE):
    "Encode key and url to hexdigest and environment variable."
    tmp = dict()
    tmp['u'] = url
    tmp['s'] = key_size
    tmp['n'] = rsa_key.n
    tmp['e'] = rsa_key.e
    tmp['d'] = rsa_key.d
    tmp['p'] = rsa_key.p
    tmp['q'] = rsa_key.q

    tmp_json = json.dumps(tmp)
    tmp_utf8 = tmp_json.encode('utf8')
    tmp_zlib = zlib.compress(tmp_utf8, 9)
    tmp_b64e = base64.b64encode(tmp_zlib)
    tmp_envk = tmp_b64e.decode('utf8')
    digest = _hash_rsa_n(rsa_key, key_size)
    return digest, tmp_envk

def decode_key(encoded):
    "Decode environment variable to url and key."
    tmp_byte = encoded.encode('utf8')
    tmp_b64e = base64.b64decode(tmp_byte)
    tmp_zlib = zlib.decompress(tmp_b64e)
    tmp_utf8 = tmp_zlib.decode('utf8')
    tmp = json.loads(tmp_utf8)
    key = rsa.PrivateKey(tmp['n'], tmp['e'], tmp['d'], tmp['p'], tmp['q'])
    key_size = tmp['s']
    digest = _hash_rsa_n(key, key_size)
    return tmp['u'], tmp['s'], digest, key
