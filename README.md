# cognito-auth server
Authorization server written in django (python) which act as the middleware between AWS Cognito and microservices architecture.
Use django admin UI to create global permissions which you can assign to users which are automatically created during an oauth flow.

## API

- GET /oauth2/token
- POST /oauth2/introspect
- POST /oauth2/refresh

## ENV file
- DEBUG
- SECRET_KEY
- DB_ENGINE
- DB_HOST
- DB_PORT
- DB_NAME
- DB_USER
- DB_PASSWORD
- REDIS_URL
- AWS_DEFAULT_REGION
- ADMIN_USERNAME
- ADMIN_PASSWORD
- ADMIN_EMAIL
- COGNITO_DOMAIN
- COGNITO_CLIENT_ID
- COGNITO_CLIENT_SECRET
- COGNITO_USERPOOL_ID
- COGNITO_REDIRECT_URL
- COGNITO_AUTH_ENDPOINT
- COGNITO_TOKEN_ENDPOINT
- COGNITO_USERINFO_ENDPOINT
