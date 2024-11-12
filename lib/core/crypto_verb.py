from enum import Enum
from Crypto.Cipher import AES

"""
Enum Verb, defines all usable crypto
TODO : add other crypto supported by Laravel
"""
class CryptoVerb(Enum):
    AES256CBC = "AES-256-CBC"
