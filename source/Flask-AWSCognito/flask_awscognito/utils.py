##Original - from flask_awscognito.constants import HTTP_HEADER
# Import Python's regex module to filter Boto3's API response 
import re
from hashlib import md5


def extract_access_token(request_headers):
    access_token = None
    # 2020-12-10 - Amazon addition
    # Purpose - Change to extract access token from passed JWT cookie
    # Original - auth_header = request_headers.get(HTTP_HEADER)
    if request_headers.get('Cookie'):
        cookies = request_headers.get('Cookie').split(';')
    # Original -  if auth_header and " " in auth_header:
        for cookie in cookies:
            if re.search('access_token=', cookie):
                _, access_token = cookie.split('=')
    # End of Amazon addition
    return access_token


def get_state(user_pool_id, user_pool_client_id):
    return md5(f"{user_pool_client_id}:{user_pool_id}".encode("utf-8")).hexdigest()
