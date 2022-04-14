import os
import re
import base64
import hashlib
import random
import string
import requests
import uuid
import json
import binascii
import time
from Crypto.PublicKey.RSA import construct
from urllib.parse import urlencode
from rest_framework.views import APIView
from rest_framework.parsers import FormParser
from rest_framework.response import Response
from django.http.response import HttpResponseRedirect, HttpResponse
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.models import User, Permission
from django.core import serializers
from operator import itemgetter
from jose import jwk as jose
from .exceptions import *

def error_handler(code):
    if code == 'invalid_request':
        raise InvalidRequestException
    elif code == 'invalid_scope':
        raise InvalidScopeException 
    elif code == 'unauthorized_client':
        raise UnauthorizedClientException
    elif code == 'invalid_grant':
        raise InvalidGrantException
    
def build_headers():
     bearer = base64.b64encode(f'{settings.COGNITO_CLIENT_ID}:{settings.COGNITO_CLIENT_SECRET}'.encode('utf-8')).decode('utf-8')
     headers = { 'Authorization': f'Basic {bearer}', 'Content-Type': 'application/x-www-form-urlencoded' } 
     return headers   


class TokenView(APIView):
    
    def __build_code_challenge(self):
      code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
      code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)
      code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
      code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
      code_challenge = code_challenge.replace('=', '')
      return code_verifier, code_challenge
  
    def __build_state(self):
      state = uuid.uuid4().hex
      return state  
  
    def __check_state(self, state):
        cached_state = cache.get(state)[0] if cache.get(state) is not None else None
        if state != cached_state:
            raise InvalidStateException
  
  
    def __authorize(self):
        state = self.__build_state()  
        code_verifier, code_challenge = self.__build_code_challenge()  
        cache.set(state, (state, code_verifier, code_challenge), 60)
        data = {
          'response_type': 'code', 
          'client_id': settings.COGNITO_CLIENT_ID,
          'redirect_uri': settings.COGNITO_REDIRECT_URL,
          'state': state,
          'code_challenge_method': 'S256',
          'scope': 'openid email profile',
          'code_challenge': code_challenge
        }
        url = f'{settings.COGNITO_DOMAIN}{settings.COGNITO_AUTH_ENDPOINT}?{urlencode(data)}'
        return HttpResponseRedirect(redirect_to=url) 
    
    def __token(self, state, code):
        code_verifier =  cache.get(state)[1] 
        data = {
          'grant_type': 'authorization_code',
          'client_id': settings.COGNITO_CLIENT_ID,
          'redirect_uri': settings.COGNITO_REDIRECT_URL,
          'code': code,
          'code_verifier': code_verifier,
        }
        url = f'{settings.COGNITO_DOMAIN}{settings.COGNITO_TOKEN_ENDPOINT}'
        resp = requests.post(url, params=data, headers=build_headers())
        resp = resp.json()
        if 'error' in resp:
          error_handler(resp['error'])  
        return resp
      
    def __user_info(self, access_token):
       headers = { 'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json;charset=UTF-8' } 
       url = f'{settings.COGNITO_DOMAIN}{settings.COGNITO_USERINFO_ENDPOINT}' 
       resp = requests.get(url, headers=headers)
       user_info = resp.json()
       User.objects.get_or_create(
         email=user_info['email'],
         username=user_info['username'],
       )
    
   
    def get(self, request):
      params = request.query_params
      if params.get('error') is not None:
        error_handler(params.get('error_description'))  
      if params.get('state') is not None:
        self.__check_state(params.get('state')) 
      if params.get('code') is None:
        return self.__authorize() 
      resp = self.__token(params.get('state'), params.get('code'))
      access_token, refresh_token = itemgetter('access_token', 'refresh_token')(resp)
      self.__user_info(access_token)
      return Response(resp)
  
  
class IntrospectView(APIView):
    
    def __get_jwk(self, token):
        header = token.split('.')[0]
        decoded = json.loads(base64.b64decode(header + '===').decode('utf-8'))
        kid = decoded['kid']
        url = f'https://cognito-idp.{settings.REGION}.amazonaws.com/{settings.COGNITO_USERPOOL_ID}/.well-known/jwks.json'
        resp = requests.get(url).json()
        jwk = next((key for key in resp['keys'] if key['kid'] == kid), None)
        if jwk is None:
            raise JWKNotFoundException
        return jwk
    
    def __b64_to_int(self, data):
      return int(binascii.hexlify(base64.urlsafe_b64decode(data + '===')), 16)
    
    def __build_pub_key(self, jwk):
      e = self.__b64_to_int(jwk['e'])
      n = self.__b64_to_int(jwk['n'])
      pub_key = construct((n, e))
      return pub_key.export_key()
  
    def __verify_exp(self, token):
        payload = token.split('.')[1]
        decoded = json.loads(base64.b64decode(payload + '===').decode('utf-8'))
        exp = decoded['exp']
        current_time = time.time()
        return current_time < exp
  
    def __verify_sig(self, token, jwk):
        message, sig = token.rsplit('.', 1)
        decoded = base64.urlsafe_b64decode(sig + '===')
        pub_key = self.__build_pub_key(jwk)
        key = jose.construct(pub_key, 'RS256')
        return key.verify(message.encode('utf-8'), decoded)
    
    def __introspect(self, token):
       jwk = self.__get_jwk(token)
       is_active = self.__verify_exp(token) and self.__verify_sig(token, jwk)
       if not is_active:
           raise InvalidTokenException 
       payload = token.split('.')[1]
       decoded = json.loads(base64.b64decode(payload + '===').decode('utf-8')) 
       user = User.objects.get(username=decoded['username'])
       scope = ' '.join([permission.codename for permission in Permission.objects.filter(user=user) | Permission.objects.filter(group__user=user)])
       data = {'active': is_active, 'sub': decoded['sub'], 'iss': decoded['iss'], 'iat': decoded['iat'], 'jti': decoded['jti'], 'exp': decoded['exp'], 'username': decoded['username'], 'scope': scope}
       return json.dumps(data)
    
    def post(self, request):
      token = request.data.get('token')  
      return HttpResponse(self.__introspect(token))
  
class RefreshView(APIView):  
    
    parser_classes = [FormParser]
    
    def __refresh(self, token):
        data = {
          'grant_type': 'refresh_token',
          'client_id': settings.COGNITO_CLIENT_ID,
          'refresh_token': token,
        }
        url = f'{settings.COGNITO_DOMAIN}{settings.COGNITO_TOKEN_ENDPOINT}'
        resp = requests.post(url, params=data, headers=build_headers())
        resp = resp.json()
        if 'error' in resp:
          error_handler(resp['error'])  
        return resp
      
    def post(self, request):
      token = request.data.get('refresh_token')  
      return Response(self.__refresh(token))