from lib.core.laravel_encrypter import LaravelEncrypter, LaravelEncrypterError

import requests
requests.packages.urllib3.disable_warnings()


def get_all_cookies(url):
    """"
    Retrieves all cookies from the given URL
    """
    session = requests.Session()

    # Mimicking a real browser
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        )
    }

    try:
        session.get(url, verify=False, allow_redirects=True,
                    headers=headers)

        if session.cookies:
            cookies = {}
            for cookie in session.cookies:
                cookies[cookie.name] = cookie.value
            return cookies
    except requests.exceptions.RequestException:
        pass

    return {}


def checker(app_url, app_key):
    """
    Checks if the APP_KEY is valid for the given URL
    """

    # Get all cookies and try to decrypt them
    cookies = get_all_cookies(app_url)
    laravel_encrypter = LaravelEncrypter(app_key)

    decrypted = {}
    for cookie in cookies:
        try:
            result = laravel_encrypter.decrypt(cookies[cookie])
            decrypted[cookie] = result
        except LaravelEncrypterError:
            continue

    return decrypted
