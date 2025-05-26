import json
import sys
import base64
import binascii
import hmac
import hashlib
import os
from lib.core.aes_encrypter import AESEncrypter
from lib.core.crypto_verb import CryptoVerb
from urllib.parse import unquote
from Crypto import Random

__all__ = [
    "LaravelEncrypterError",
    "LaravelEncrypter"
]

class LaravelEncrypterError(Exception):
    """Raises when LaravelEncrypter cannot decrypt a value."""

"""
Class used to encrypt and decrypt data with Laravel logic
TODO : add other crypto supported by Laravel
"""
class LaravelEncrypter:

    """
    A key can be defined directly
    """
    def __init__(self, key=None):
        self.key = key
        self.crypto = CryptoVerb.AES256CBC
    

    """
    Encrypts a base64 string as a ciphered Laravel value
    """
    def encrypt(self, value_to_encrypt):
        key = self.retrieve_key(self.key)
        iv = Random.get_random_bytes(16) # The iv doesn't matter
        aes_encrypter = AESEncrypter()
        tmp_bytes = base64.b64encode(aes_encrypter.aes_encrypt(base64.b64decode(value_to_encrypt), iv, key))
        b64_iv=base64.b64encode(iv).decode("ascii")
        data = {}
        data['iv'] = b64_iv
        data['value'] = tmp_bytes.decode("ascii")
        data['mac'] = hmac.new(key,(b64_iv+data['value']).encode("ascii"), hashlib.sha256).hexdigest()
        data['tag'] = ''
        return base64.b64encode(json.dumps(data).encode("ascii"))
    
    """
    Encrypts a base64 string as a Laravel session cookie.
    The parameter hash_value needs to be the same as the decrypted value of the Laravel session cookie.
    """
    def encrypt_session_cookie(self, value_to_encrypt, hash_value):
        decoded_value = base64.b64decode(value_to_encrypt).decode('utf-8')
        parsed_value = decoded_value.replace('\\','\\\\').replace('"','\\"').replace('\00','\\u0000')
        session_json_to_encrypt = f'{hash_value}|{{"data":"{parsed_value}","expires":9999999999}}'
        return self.encrypt(base64.b64encode(session_json_to_encrypt.encode()))

    """
    When a data is encrypted with Laravel, it will become a base64 version of the JSON
    {"iv":<b64_iv>, "value":<b64_value>, "mac":<mac>}
    Therefore, before decrypting it, it is required to parse its data
    We don't have usage for the mac value when decrypting, therefore it is not used
    """
    def parse_laravel_cipher(self, laravel_cipher):

        # Data is often in cookie or URLs, therefore this line decodes URL to be sure
        laravel_cipher = unquote(laravel_cipher)
        try:
            data = json.loads(base64.b64decode(laravel_cipher))
        except json.decoder.JSONDecodeError:
            raise LaravelEncrypterError("[-] The JSON inside your base64 is malformed")
            sys.exit(1)
        except (binascii.Error, UnicodeDecodeError):
            raise LaravelEncrypterError("[-] your base64 laravel_cipher value is malformed")
            sys.exit(0)
        data["value"] = base64.b64decode(data["value"])
        data["iv"] = base64.b64decode(data["iv"])
        return data

    """
    Parse laravel APP_KEY value
    """
    def retrieve_key(self, key):
        if key.startswith('base64:'):
           return base64.b64decode(key.split(":")[1])
        if len(key) == 44 :
            return base64.b64decode(key)
        return key.encode()

    """
    decrypts a Laravel ciphered string
    """
    def decrypt(self, laravel_cipher):
        data = self.parse_laravel_cipher(laravel_cipher)
        key = self.retrieve_key(self.key)
        
        try:
            if self.crypto.value == "AES-256-CBC":
                aes_encrypter = AESEncrypter()
                result = aes_encrypter.aes_decrypt(data["value"], data["iv"], key)
                return result
        except ValueError:
            raise LaravelEncrypterError("[-] Your key is probably malformed or incorrect.")
        return False

    """
    Uses an opened file containing a key on each line to perform a bruteforce attack on a given value
    Returns the valid key if it was identified with the value :
    {"key":<key>, "value":<value>}
    """
    def bruteforce_from_file(self, key_file, value):
        found = False
        result = ""
        for line in key_file:
            try:
                self.key = line.strip()
                key = self.retrieve_key(self.key)
                result = {"key": self.key, "value": self.decrypt(value).decode("utf-8")}
                found = True
                break
            except LaravelEncrypterError:
                continue
            except:
                continue
        if not found:
            return False
        return result

