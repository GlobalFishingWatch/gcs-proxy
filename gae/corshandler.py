import webapp2


class CORSHandler(webapp2.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(CORSHandler, self).__init__(*args, **kwargs)
        self.CORS_origins = '*'
        self.CORS_methods = ['POST', 'GET', 'OPTIONS']
        self.CORS_headers = ['Origin', 'X-Requested-With', 'Content-Type', 'Accept']
        self.CORS_allow_credentials = True

    def dispatch(self):
        origins = self.CORS_origins
        if 'Access-Control-Request-Method' not in self.request.headers:
            super(CORSHandler, self).dispatch()
        if origins == "*" and self.CORS_allow_credentials and 'Referer' in self.request.headers:
            origins = "/".join(self.request.headers['Referer'].split("/")[:3])
        self.response.headers['Access-Control-Allow-Origin'] = origins
        if self.CORS_allow_credentials: self.response.headers['Access-Control-Allow-Credentials'] = 'true'
        self.response.headers['Access-Control-Allow-Methods'] = ', '.join(self.CORS_methods)
        self.response.headers['Access-Control-Allow-Headers'] = ', '.join(self.CORS_methods)
