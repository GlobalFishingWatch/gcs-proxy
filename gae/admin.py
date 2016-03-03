import virtualenvloader
import webapp2
import jinja2
import os
from google.appengine.api import memcache
import config
import authentication


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)



class MainPage(webapp2.RequestHandler):
    @authentication.require("admin", "admin_cache", "admin_tilesets", "admin_users", "admin_view_users")
    def get(self):
        user = authentication.get_current_user(self.request)
        template_values = {'appversion': config.APP_VERSION,
                           'allowed_users': authentication.is_member(user, "user-admin"),
                           'allowed_groups': authentication.is_member(user, "groups-admin"),
                           'allowed_access': authentication.is_member(user, "access-admin"),
                           'allowed_admin': authentication.is_member(user, "admin")
                           }

        template_values['env']=[{'key': k, 'value': os.environ[k]} for k in sorted(os.environ)]

        template = JINJA_ENVIRONMENT.get_template('index.html')
        self.response.write(template.render(template_values))

class UsersPage(webapp2.RequestHandler):
    @authentication.require("admin", "admin_users", "admin_view_users")
    def get(self):
        template_values = {
            'users': authentication.list_users(),
            'groups': authentication.list_groups()
            }

        template = JINJA_ENVIRONMENT.get_template('users.html')
        self.response.write(template.render(template_values))

    @authentication.require("admin", "admin_users")
    def post(self):
        update = {}
        for key, value in self.request.POST.iteritems():
            row, field = key.split("__")
            if row not in update:
                update[row] = {'groups': []}
            if field.startswith('groups_'):
                group = field[len('groups_'):]
                update[row]['groups'].append(group)
            else:
                update[row][field] = value

        for item in update.itervalues():
            user = authentication.User(email = item['email'], is_admin=False)
            authentication.remove_memberships(user)
            authentication.make_member(user, *item['groups'])

        self.redirect('/admin/users')

class GroupsPage(webapp2.RequestHandler):
    @authentication.require("admin", "admin_group", "admin_view_group")
    def get(self):
        template_values = {
            'groups': authentication.list_groups()
            }

        template = JINJA_ENVIRONMENT.get_template('groups.html')
        self.response.write(template.render(template_values))

    @authentication.require("admin", "admin_group")
    def post(self):
        update = {}
        for key, value in self.request.POST.iteritems():
            group, attribute = key.split("__")
            if group not in update:
                update[group] = {}
            update[group][attribute] = value

        for group in update.itervalues():
            if 'add' in group:
                authentication.make_group(group['name'])                    
            elif 'delete' in group:
                authentication.remove_group(group['name'])

        self.redirect('/admin/groups')

class AccessPage(webapp2.RequestHandler):
    @authentication.require("admin", "admin_access", "admin_view_access")
    def get(self):
        template_values = {
            'access': authentication.list_access()
            }

        template = JINJA_ENVIRONMENT.get_template('acl.html')
        self.response.write(template.render(template_values))

    @authentication.require("admin", "admin_access")
    def post(self):
        update = {}
        for key, value in self.request.POST.iteritems():
            group, item, attribute = key.split("__")
            if group not in update:
                update[group] = {}
            if item not in update[group]:
                update[group][item] = {}
            update[group][item][attribute] = value

        for group in update.itervalues():
            for item in group.itervalues():
                if 'add' in item:
                    authentication.set_access(item['group'], item['path'], 'access' in item)                    
                elif 'delete' in item:
                    authentication.unset_access(item['group'], item['path'])

        self.redirect('/admin/access')


app = webapp2.WSGIApplication([
    ('/admin', MainPage),
    ('/admin/users', UsersPage),
    ('/admin/groups', GroupsPage),
    ('/admin/access', AccessPage)
], debug=True)
