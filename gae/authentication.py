import virtualenvloader
import google.appengine.ext.ndb
import google.appengine.api
import webapp2
import jinja2
import os.path
import config
import json
import hashlib
import logging
import slugify
import urllib

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

class Group(google.appengine.ext.ndb.Model):
    name = google.appengine.ext.ndb.StringProperty()
    info = google.appengine.ext.ndb.JsonProperty()

class Member(google.appengine.ext.ndb.Model):
    group = google.appengine.ext.ndb.StringProperty()
    email = google.appengine.ext.ndb.StringProperty()

class Person(google.appengine.ext.ndb.Model):
    email = google.appengine.ext.ndb.StringProperty()
    info = google.appengine.ext.ndb.JsonProperty()

class Access(google.appengine.ext.ndb.Model):
    group = google.appengine.ext.ndb.StringProperty()
    path = google.appengine.ext.ndb.StringProperty()
    access = google.appengine.ext.ndb.BooleanProperty()
    

class User(object):
    def __new__(cls, serialized=None, **values):
        if serialized != None:
            h, j = serialized.split(":", 1)
            if cls._hash(j) != h:
                return None
            v = json.loads(j)
            v.update(values)
            values = v
        self = object.__new__(cls)
        object.__setattr__(self, 'values', values)
        return self
    def __init__(self, *arg, **kw):
        pass

    def __getattr__(self, key):
        if key not in self.values:
            raise AttributeError(key)
        return self.values[key]
    def __delattr__(self, key):
        if key not in self.values:
            raise AttributeError(key)
        del self.values[key]
    def __setattr__(self, key, value):
        self.values[key] = value

    @classmethod
    def _hash(cls, str):
        return hashlib.sha224(config.SERVER_SECRET + str).hexdigest()

    def serialize(self):
        res = json.dumps(self.values)
        return self._hash(res) + ":" + res

if config.TEST_SERVER:
    current_test_user = User(nickname = 'test',
                             email = 'test@example.com',
                             user_id = 'test',
                             federated_identity = 'test',
                             federated_provider = 'test',
                             is_admin = True
                             )

def get_current_user(request):
    if config.TEST_SERVER and current_test_user is not None:
        return current_test_user
    user = google.appengine.api.users.get_current_user()
    if user:
        return User(nickname = user.nickname(),
                    email = user.email(),
                    user_id = user.user_id(),
                    federated_identity = user.federated_identity(),
                    federated_provider = user.federated_provider(),
                    is_admin = google.appengine.api.users.is_current_user_admin()
                    )
    elif "pelagos-auth" in request.cookies:
        return User(request.cookies["pelagos-auth"], from_cookie=True)
    return None

def set_auth(response, user):
    if user is None:
        response.delete_cookie("pelagos-auth", domain=os.environ['SERVER_NAME'])
    elif getattr(user, "from_cookie", False) is False:
        domain = os.environ['SERVER_NAME']
        response.set_cookie("pelagos-auth", value=user.serialize(), domain=os.environ['SERVER_NAME'], overwrite=True)
    return response

def is_member(user, *group_names):
    nomalized_email = user.email.lower()
    memberships = Member.query(google.appengine.ext.ndb.AND(
        Member.group.IN(group_names),
        Member.email == nomalized_email))
    for membership in memberships:
        return membership
    if user.is_admin:
        return True
    return None

def make_member(user, *group_names):
    for group_name in group_names:
        if is_member(user, group_name):
            continue
        member = Member(
            email = user.email.lower(),
            group=group_name)
        member.put()

def remove_memberships(user):
    memberships = list(Member.query(Member.email == user.email.lower()))
    for membership in memberships:
        membership.key.delete()

def list_groups():
    names = [group.name for group in Group.query()]
    names.sort()
    return names

def make_group(name, info = {}):
    group = Group(
        name = name,
        info = info)
    group.put()

def remove_group(name):
    groups = list(Group.query(Group.name == name))
    for group in groups:
        group.key.delete()
    accesses = list(Access.query(Access.group == name))
    for access in accesses:
        access.key.delete()
    members = list(Member.query(Member.group == name))
    for member in members:
        member.key.delete()


def list_users(*group_names):
    if group_names:
        group_names = Member.group.IN(group_names)
    users = {}
    for membership in Member.query(*group_names):
        if membership.email not in users:
            users[membership.email] = []
        users[membership.email].append(membership.group)
    users = [{'slug': slugify.slugify(key, separator="_"),
            'email': key,
            'groups': value}
           for key, value in users.iteritems()]
    for membership in users:
        membership['groups'].sort()
        for person in Person.query(Person.email == membership['email']):
            membership['info'] = person.info
            break
    users.sort(lambda a, b: cmp(a['email'], b['email']))
    return users;

def list_access():
    acls = {group: [] for group in list_groups()}

    for access in Access.query():
        if access.group not in acls:
            acls[access.group] = []
        acls[access.group].append(access)
    
    for group in acls:
        acls[group].sort(lambda a, b: cmp(a.path, b.path))
    
    return acls

def set_access(group, path, access):
    a = Access(
        group = group,
        path = path,
        access = access)
    a.put()

def unset_access(group, path):
    accesses = list(Access.query(Access.group == group, Access.path == path))
    for access in accesses:
        access.key.delete()

def require(*groups, **options):
    def wrap(fn):
        def wrapper(self, *arg, **kw):
            user = get_current_user(self.request)
            if user:
                if wrapper.is_allowed(user):
                    fn(self, *arg, **kw)
                else:
                    logging.warning('Authentication failure: %s' % (user.email.lower()))
                    if options.get('redirect', True):
                        self.redirect('/auth/restricted?continue=' + urllib.quote_plus(self.request.url))
                    else:
                        self.response.status = "403 Not authorized"
                        self.response.write(json.dumps({
                            "auth_location": '/auth/restricted?continue=/auth/login/done'
                        }))
            else:
                if options.get('redirect', True):
                    self.redirect('/auth/login?continue=' + urllib.quote_plus(self.request.url))
                else:
                    self.response.status = "403 Not authenticated"
                    self.response.write(json.dumps({
                        "auth_location": popup_login_url(self.request)
                    }))
            set_auth(self.response, user)
        def is_allowed(user):
            if not groups:
                return True
            return is_member(user, *groups)
        wrapper.is_allowed = is_allowed
        return wrapper
    return wrap

class LogoutHandler(webapp2.RequestHandler):
    def get(self):
        set_auth(self.response, None)
        self.redirect(google.appengine.api.users.create_logout_url(self.request.get('continue', '/')))

class RestrictedHandler(webapp2.RequestHandler):
    def get(self):
        user = google.appengine.api.users.get_current_user()
        if user: user = user.email()
        login_url = '/auth/login?continue=' + self.request.get('continue', '/')
        logout_url = '/auth/logout?continue=' + urllib.quote_plus(login_url)
        self.response.write(
            JINJA_ENVIRONMENT.get_template('views/restricted/restricted.html').render(
                {"login_url": login_url,
                 "logout_url": logout_url,
                 "user": user,
                 "contact_url": config.CONTACT_URL,
                 "google_analytics_code": config.GOOGLE_ANALYTICS_CODE,
                 "page_title": 'Global Fishing Watch - Unauthorized Access'}))

def popup_login_url(request):
    return 'http://' + os.environ['HTTP_HOST'] + '/auth/login/google?continue=/auth/login/done'

def redirect_login_url(request):
    return 'http://' + os.environ['HTTP_HOST'] + '/auth/login/google?continue=' + urllib.quote_plus(request.get('continue', '/'))

class LoginHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(
            JINJA_ENVIRONMENT.get_template('views/login.html').render(
                {"popup_login_url": popup_login_url(self.request),
                 "redirect_login_url": redirect_login_url(self.request),
                 "continue_url": self.request.get('continue', '/')}))

class LoginDoneHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(
            JINJA_ENVIRONMENT.get_template('views/login-done.html').render(
                {'success': get_current_user(self.request) is not None}))

class LoginGoogleHandler(webapp2.RequestHandler):
    def get(self):
	self.redirect(str(self.request.get('continue', '/')))

class AuthTestHandler(webapp2.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(AuthTestHandler, self).__init__(*args, **kwargs)

    def get(self):
        noauth_url = self.request.get('noauth_url', None)

        user = get_current_user(self.request)

        template_values = dict(email='',
                               status='Not Logged In',
                               logout_url=google.appengine.api.users.create_logout_url(self.request.url),
                               login_url=google.appengine.api.users.create_login_url(self.request.url),
                               noauth_url=noauth_url)
        if user:
            template_values['email'] = user.email
            template_values['status'] = 'Logged In'
            if is_member(user, "viz"):
                template_values['authorized'] = 'Authorized'

        if noauth_url and template_values['authorized'] != 'Authorized':
            self.redirect(noauth_url)

        self.response.write(
            JINJA_ENVIRONMENT.get_template('authtest.html').render(template_values))

# Redirect loops
## Redirect auth
#  1 /auth/restricted?continue=REFERER_URL
#    If logged in
#      2 /auth/login?continue=REFERER_URL
#      5 REFERER_URL
#    Else
#      3 /auth/logout?continue=QUOTE(/auth/login?continue=REFERER_URL)
#      4 /auth/login?continue=REFERER_URL
#      5 REFERER_URL

## Popup auth
#  1 /auth/restricted?continue=/auth/login/done
#    If logged in
#      2 /auth/login?continue=/auth/login/done
#      5 /auth/login/done
#    Else
#      3 /auth/logout?continue=QUOTE(/auth/login?continue=/auth/login/done)
#      4 /auth/login?continue=/auth/login/done
#      5 /auth/login/done

app = webapp2.WSGIApplication([
    ('/auth/logout', LogoutHandler),
    ('/auth/restricted', RestrictedHandler),
    ('/auth/login/google', LoginGoogleHandler),
    ('/auth/login/done', LoginDoneHandler),
    ('/auth/login', LoginHandler),
    ('/auth/test', AuthTestHandler)
], debug=True)
