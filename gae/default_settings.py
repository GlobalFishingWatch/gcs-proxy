import os
import os.path

SERVER_DIR=os.path.dirname(__file__)

# NB: When running unit tests in NOSEGAE, os.environ is not set up by
# the time we get here
SERVER_SOFTWARE = os.environ.get('SERVER_SOFTWARE', 'Development-NOSEGAE')
DEV_SERVER = SERVER_SOFTWARE.startswith('Development')
TEST_SERVER = SERVER_SOFTWARE == 'Development-NOSEGAE'
PROD_SERVER = SERVER_SOFTWARE.startswith('Google App Engine/')

try:
    import google.appengine.api.app_identity
    APPLICATION_ID = google.appengine.api.app_identity.get_application_id()
except:
    if 'APPLICATION_ID' in os.environ:
        APPLICATION_ID = os.environ['APPLICATION_ID']
    else:
        import subprocess
        import ConfigParser
        cp = ConfigParser.ConfigParser()
        cp.readfp(subprocess.Popen(
                ["gcloud", "config", "list"],
                stdout=subprocess.PIPE).stdout)
        APPLICATION_ID = cp.get("core", "project")

APP_VERSION = os.environ.get('CURRENT_VERSION_ID', 'unittest')

try:
    with open(os.path.join(os.path.dirname(__file__), "server_secret.txt")) as f:
        SERVER_SECRET = f.read().strip()
except Exception, e:
    pass

CONTACT_URL=''
