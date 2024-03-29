from .base import *

REGION = env('AWS_DEFAULT_REGION')
COGNITO_DOMAIN = env('COGNITO_DOMAIN')
COGNITO_CLIENT_ID = env('COGNITO_CLIENT_ID')
COGNITO_CLIENT_SECRET = env('COGNITO_CLIENT_SECRET')
COGNITO_USERPOOL_ID = env('COGNITO_USERPOOL_ID')
COGNITO_REDIRECT_URL = env('COGNITO_REDIRECT_URL')
COGNITO_AUTH_ENDPOINT = env('COGNITO_AUTH_ENDPOINT')
COGNITO_TOKEN_ENDPOINT = env('COGNITO_TOKEN_ENDPOINT')
COGNITO_USERINFO_ENDPOINT = env('COGNITO_USERINFO_ENDPOINT')