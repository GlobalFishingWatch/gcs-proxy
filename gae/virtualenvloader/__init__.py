import os

# Workaround for Google App Engine (and its dev environment)
if 'PATH' not in os.environ:
    os.environ['PATH'] = ''

def find_virtualenv(path = __file__):
    while path and path != '/':
        if os.path.exists(os.path.join(path, 'bin/activate_this.py')):
            return path
        path = os.path.dirname(path)
    raise Exception("Unable to find virtualenv")

virtualenv = find_virtualenv(os.path.join(os.path.dirname(__file__), 'gaevirtualenv'))
activate = os.path.join(virtualenv, 'bin/activate_this.py')
execfile(activate, dict(__file__=activate))
os.environ['VIRTUAL_ENV'] = virtualenv