from rest_framework.exceptions import APIException

class InvalidRequestException(APIException):
    status_code = 400
    default_detail = 'Response_type is not included or code_challenge is supplied but code_challenge_method is not supplied or if code_challenge_method is not S256'

class InvalidScopeException(APIException):
    status_code = 400
    default_detail = 'Unknown or malformed scope'
    
class InvalidStateException(APIException):
    status_code = 400
    default_detail = 'Unknown or malformed state'    
    
class InvalidGrantException(APIException):
    status_code = 400
    default_detail = 'Invalid grant type'    
    
class UnauthorizedClientException(APIException):
    status_code = 401
    default_detail = 'Client does not have permission for code or token requests'   
    
class InvalidTokenException(APIException):
     status_code = 401
     default_detail = 'Invalid token'       
    
class JWKNotFoundException(APIException):
    status_code = 404
    default_detail = 'JSON Web Key not found'     