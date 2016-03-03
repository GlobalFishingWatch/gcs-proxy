import virtualenvloader
import webapp2
import json
from corshandler import CORSHandler
import logging
import config
import datetime
import authentication
import jsonview
import memcaching
import config
import io
import apiclient.http
import googleapi

def load_file(path):
    if path.startswith("gs://"):
        path = path[len("gs://"):]
    if path.startswith("/"):
        path = path[1:]
    bucket_name, object_name = path.split("/", 1)
    req = googleapi.storage.objects().get_media(
        bucket=bucket_name,
        object=object_name)
    fh = io.BytesIO()
    downloader = apiclient.http.MediaIoBaseDownload(fh, req, chunksize=1024*1024)
    done = False
    while not done:
        status, done = downloader.next_chunk()
    return fh.getvalue()

def load_file_metadata(path):
    if path.startswith("gs://"):
        path = path[len("gs://"):]
    if path.startswith("/"):
        path = path[1:]
    bucket_name, object_name = path.split("/", 1)
    req = googleapi.storage.objects().get(
        bucket=bucket_name,
        object=object_name,
        fields='bucket,name,contentDisposition,contentEncoding,contentType,md5Hash')
    return req.execute()

class ProxyHandler(CORSHandler):
    @authentication.require_path_acess()
    @memcaching.cached(use_cached=True)
    def get(self, path):
        self.response.headers['Content-Type'] = load_file_metadata(path)['contentType'].encode('utf-8')
        self.response.write(load_file(path))

app = webapp2.WSGIApplication([
    webapp2.Route('/proxy<path:.*>', handler=ProxyHandler, name='proxy')
], debug=True)
