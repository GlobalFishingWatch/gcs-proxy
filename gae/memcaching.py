try:
    from google.appengine.api import memcache, taskqueue
except:
    class FakeCache(object):
        def __init__(self):
            self.data = {}
        def get(self, key, namespace=''):
            if (namespace, key) not in self.data:
                return None
            return self.data[(namespace, key)]
        def set(self, key, value, namespace=''):
            self.data[(namespace, key)] = value
    memcache = FakeCache()

    taskqueue = None

import hashlib
import webob
import StringIO
import time

def cached(*arg, **kw):
    if not kw and len(arg) == 1 and callable(arg[0]):
        return _cached(*arg)
    def cached(fn):
        return _cached(fn, *arg, **kw)
    return cached

def _cached(fn, use_cached = False, max_age = None, eventually_consistent = None):
    def cached(self, *arg, **kw):
        use_cached_val =  use_cached
        if self.request.get('use_cached', None) is not None:
            use_cached_val = self.request.get('use_cached') == 'true'

        key = hashlib.sha1(self.request.method)
        key.update(self.request.url)
        key.update(self.request.body)
        key = key.hexdigest()
        
        if use_cached_val:
            cached = memcache.get(key=key, namespace="cached_view")
            if cached is not None:
                age = time.time() - cached['time']
                if max_age is None or age < max_age:
                    if eventually_consistent is not None and age > eventually_consistent:
                        local_url = '/' + self.request.url.split("://")[1].split("/", 1)[1]
                        if 'use_cached=true' not in local_url:
                            sep = "?"
                            if '?' in local_url:
                                sep = "&"
                            local_url = local_url + sep + 'use_cached=false'
                        else:
                            local_url = local_url.replace('use_cached=true', 'use_cached=false')

                        retry_options = taskqueue.TaskRetryOptions(task_retry_limit=1)
                        que = taskqueue.Queue("memcaching-eventually-consistency")
                        que.add_async(taskqueue.Task(
                                url=local_url,
                                method=self.request.method,
                                payload=self.request.body,
                                headers=self.request.headers,
                                retry_options=retry_options))


                    response = webob.Response.from_file(StringIO.StringIO(cached['value']))
                    for name in response.__dict__:
                        setattr(self.response, name, getattr(response, name))
                    self.cache_hit = True
                    return

        fn(self, *arg, **kw)

        memcache.set(key=key, value={'value': str(self.response), 'time': time.time()}, namespace="cached_view")
    return cached
