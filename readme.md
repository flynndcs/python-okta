# Installation

- adapted from https://developer.okta.com/docs/guides/sign-into-web-app-redirect/python/main/

- export OKTA_OAUTH2_ISSUER=https://${yourOktaDomain}/oauth2/${authorizationServerId}
- export OKTA_OAUTH2_CLIENT_ID=${myWebAppclientId}
- export OKTA_OAUTH2_CLIENT_SECRET=${myWebAppclientSecret}
- export OKTA_OAUTH2_SERVICE_APP_CLIENT_ID=${myWebAppclientId}
- export OKTA_SERVICE_APP_SECRET=${myAPIServicesAPP1Secret}
- export OKTA_NATIVE_APP_CLIENT_ID={myNativeAppClientId}

- pip install requests==2.27.1 Flask==2.0.2 flask-cors==3.0.10 pyOpenSSL==22.0.0 Flask-Login==0.5.0 shapely==2.0.1
- export FLASK_APP=app
- flask run