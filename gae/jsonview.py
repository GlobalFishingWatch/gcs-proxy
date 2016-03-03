import json

def jsonview(fn):
    def wrapper(self, *arg, **kw):
        try:
            fn(self, *arg, **kw)
        except Exception, e:
            import traceback
            self.error(500)
            self.response.write(json.dumps({
                "error": str(e),
                "stack": traceback.format_exc()
            }))
    return wrapper
