import binascii
import json
import sys
import base64
from lib.core.crypto_verb import CryptoVerb
from Cryptodome.Cipher import AES

"""
Class used to perform an AES encryption compatible with Laravel
TODO : add other crypto supported by Laravel
"""
class AESEncrypter:

    """
    Perform an AES encryption
    """
    def aes_encrypt(self, value, iv, key):
        value = value.decode("utf-8")
        aes_cipher=AES.new(key=key,mode=AES.MODE_CBC,IV=iv)
        #Padding
        pad = lambda s : s+chr(16-len(s)%16)*(16-len(s)%16)
        returned_value = pad(value).encode("utf8")
        encrypted_value = aes_cipher.encrypt(returned_value)
        return encrypted_value
    
    """
    Decrypts an AES encrypted value
    """
    def aes_decrypt(self, encrypted_value, iv, key):
        try:
            crypt_object=AES.new(key=key,mode=AES.MODE_CBC,IV=iv)
            result = crypt_object.decrypt(encrypted_value)
            test = result.decode("utf-8")
            return result
        except binascii.Error:
            print("[-] Invalid base64-encoded string used on arguments --cookie or --key")
            return False
        except ValueError:
            raise ValueError("[-] Your key is probably malformed or incorrect.")
        except:
            print("[-] An error occured, check your dependencies then please refer to the documentation.")
            sys.exit(1)
