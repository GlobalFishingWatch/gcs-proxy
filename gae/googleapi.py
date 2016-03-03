import apiclient.discovery
import httplib2
import apiclient.discovery
import oauth2client.client

import os

import config

scope = ['https://www.googleapis.com/auth/bigquery',
         #'https://www.googleapis.com/auth/devstorage.read_only',
         'https://www.googleapis.com/auth/devstorage.read_write']

if 'SERVER_SOFTWARE' in os.environ:
    import oauth2client.appengine
    credentials = oauth2client.appengine.AppAssertionCredentials(scope=scope)
else:
    with file(config.UNITTEST_GOOGLEAPI_AUTH_KEY_FILE, 'rb') as f:
        key = f.read()

    credentials = oauth2client.client.SignedJwtAssertionCredentials(
        config.UNITTEST_GOOGLEAPI_AUTH_USER_EMAIL,
        key, scope=scope)

http = credentials.authorize(httplib2.Http(disable_ssl_certificate_validation=True))

bigquery = apiclient.discovery.build('bigquery', 'v2', http=http)
storage = apiclient.discovery.build('storage', 'v1', http=http)
