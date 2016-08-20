import os
import jinja2
import webapp2
import hmac

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)
SECRET = "you'll never get it out of me"

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def check_secure_val(self, cookie_value):
        return cookie_value

    def make_secure_val(self, value):
        return value

    def make_secure_cookie(self, name, value):
        cookie_val = self.make_secure_val(value)
        cookie_val = '%s=%s; Path=/' % (name, cookie_val)
        cookie_val = cookie_val.encode('utf-8')
        self.response.headers.add_header('Set-Cookie', cookie_val)

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        username = self.read_secure_cookie('username')
        self.user = username and User.query(User.username == username).get()

# ENDPOINTS
class PostListHandler(Handler):
    def get(self):

        if not self.user:
            print "No User - Access Denied"
            return
        
        posts = [{"title": "Why is cory so cool? <marquee>HAHAHA</marquee>"}, {"title": "Cory Is So Awesome!"}]
        self.render("list.html", coolname="CORY", posts=posts)

class UserHandler(Handler):
    def get(self):
        self.render("register.html", userForm = UserForm(None))

    def post(self):
        userForm = UserForm(self.request.POST)

        if not userForm.validate():
		self.render("register.html", userForm = userForm) 
                return

	userForm.toModel().put()
        self.make_secure_cookie('username', userForm.username)
        self.redirect('/posts')

class AuthHandler(Handler):
    def get(self):
        self.render("auth.html", authForm = AuthForm(None))

    def post(self):
        authForm = AuthForm(self.request.POST)

        if not authForm.validate():
            self.render("auth.html", authForm = authForm)
            return

        user = User.query(User.username == authForm.username, User.password == hmac.new(SECRET, authForm.password).hexdigest()).get()

        if not user:
            authForm.username_error = "Incorrect username or password"
            self.render("auth.html", authForm = authForm)
        else:
            self.make_secure_cookie('username', user.username)
            self.redirect('/posts')

# FORMS
class UserForm:
    def __init__(self, post_data):
        self.username_error = ""
        self.email_error = ""
        self.password_error = ""
        self.password_verify_error = ""

        self.username = ""
        self.email    = ""
        self.password = ""
        self.password_verify = ""

        if post_data is not None:
            self.username = post_data.get("username", "")
            self.email    = post_data.get("email", "")
            self.password = post_data.get("password", "")
            self.password_verify = post_data.get("password_verify", "")

    def validate(self):
        valid = True
        if self.username == "":
            self.username_error = "Enter a username"
            valid = False
        if self.email == "":
            self.email_error = "Enter an email"
            valid = False
        if self.password == "":
            self.password_error = "Enter a password"
            valid = False
        elif self.password_verify == "":
            self.password_verify_error = "Enter password verification"
            valid = False
        elif self.password_verify != self.password:
            self.password_verify_error = "Passwords must match"
            valid = False

        return valid

    def toModel(self):
        return User(username = self.username, email = self.email, password = hmac.new(SECRET, self.password).hexdigest(), id = self.username)

class AuthForm:
    def __init__(self, post_data):

        self.username_error = ""
        self.password_error = ""

        self.username = ""
        self.password = ""

        if post_data is not None:
            self.username = post_data.get("username", "")
            self.password = post_data.get("password", "")
            
    def validate(self):

        valid = True
        if self.username == "":
            self.username_error = "Enter a Username"
            valid = False
        if self.password == "":
            self.password_error = "Enter a Password" 
            valid = False

        return valid

# MODELS
class User(ndb.Model):
    username = ndb.StringProperty(required = True)
    email = ndb.StringProperty(required = True)
    password = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    modified = ndb.DateTimeProperty(auto_now = True)

app = webapp2.WSGIApplication([('/posts', PostListHandler), ('/users', UserHandler), ('/auth', AuthHandler)], debug=True)
