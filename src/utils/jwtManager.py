"""

 (c) Copyright Ascensio System SIA 2024

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

"""

import jwt
from src.configuration import ConfigurationManager
from functools import wraps
from django.http import JsonResponse

config_manager = ConfigurationManager()


# check if a secret key to generate token exists or not
def isEnabled():
    return bool(config_manager.jwt_secret())


# check if a secret key to generate token exists or not
def useForRequest():
    return config_manager.jwt_use_for_request()


# encode a payload object into a token using a secret key and decodes it into the utf-8 format
def encode(payload):
    return jwt.encode(payload, config_manager.jwt_secret(), algorithm='HS256')


# decode a token into a payload object using a secret key
def decode(string):
    return jwt.decode(string, config_manager.jwt_secret(), algorithms=['HS256'])


# Decorator for token validation
def token_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        token = request.headers.get(config_manager.jwt_header())
        if token:
            token = token[len('Bearer '):]
            try:
                payload = decode(token)
                request.payload = payload  # Attach the payload to the request
            except jwt.ExpiredSignatureError:
                return JsonResponse({"error": "Token has expired"}, status=403)
            except jwt.InvalidTokenError:
                return JsonResponse({"error": "Invalid token"}, status=403)
        else:
            return JsonResponse({"error": "Token is not present"}, status=403)
        return view_func(request, *args, **kwargs)
    return _wrapped_view