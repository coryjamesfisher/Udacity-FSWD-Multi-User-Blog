import os
import jinja2
import webapp2
import hmac
import urllib
from markupsafe import Markup

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def urlencode_filter(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = s.encode('utf8')
    s = urllib.quote_plus(s)
    return Markup(s)

jinja_env.filters['urlencode'] = urlencode_filter
SECRET = "you'll never get it out of me"

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(dict(params, user=self.user))

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

    def delete_cookie(self, name):
        self.response.headers.add_header('Set-Cookie', name + "=;")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        username = self.read_secure_cookie('username')
        self.user = username and User.query(User.username == username).get()

# ENDPOINTS
class PostListHandler(Handler):
    def get(self):

        ancestor = None
        pageTitle = "All Posts - All Authors"

        if self.request.get("owner", ""):
            ancestor = ndb.Key(User, self.request.get("owner"))
            pageTitle = "All Posts - " + self.request.get("owner")
            

        query = Post.query(ancestor = ancestor).order(-Post.created)
        posts = query.fetch(10, offset = 0)
        self.render("list.html", posts=posts, pageTitle = pageTitle)


class PostHandler(Handler):
    def get(self):
        post = None
        comments = None

        if not self.user:
            print "No User - Access Denied"
            return

        if self.request.get("post_key", "") != "":
            postKey = ndb.Key(urlsafe = self.request.get("post_key"))
            post = postKey.get()
            comments = Comment.query(ancestor = postKey).fetch(100)

        if not self.request.get("edit", ""):
            if not post:
                self.redirect('/posts')
                return

            self.render("post/view.html", post = post, comments = comments)
            return

        postForm = PostForm(None)

        if post and post.owner == self.user.username:
	    postForm.post_key = post.key.urlsafe()
            postForm.title = post.title
            postForm.content = post.content

        self.render("post/edit.html", postForm = postForm)

    def post(self):
        postForm = PostForm(self.request.POST)

        if not postForm.validate():
            self.render("post/edit.html", postForm = postForm)
            return

        if postForm.post_key:
            postKey = ndb.Key(urlsafe = self.request.get("post_key"))
            post = postKey.get()

            if post.owner != self.user.username:
                # todo add error message
                self.redirect('/post?post_key=' + post.key.urlsafe())
                return

        else:
            post.owner = self.user.username
            postId = ndb.Model.allocate_ids(size=1, parent=self.user.key)[0]
            post.key = ndb.Key("Post", postId, parent=self.user.key)

        post.title = postForm.title 
        post.content = postForm.content
        post.put()
        self.redirect('/post?post_key=' + post.key.urlsafe())


class CommentHandler(Handler):
    def post(self):
        commentForm = CommentForm(self.request.POST)

        if not commentForm.validate():

            print "crappy error validating comment form"
            return

        comment  = commentForm.toModel()
        comment.owner = self.user.username

	postKey = ndb.Key(urlsafe = commentForm.post)
        commentId = ndb.Model.allocate_ids(size=1, parent=postKey)[0]
        comment.key = ndb.Key("Comment", commentId, parent=postKey)

        comment.put()
        self.redirect('/post?post_key=' + commentForm.post)


class RegisterHandler(Handler):
    def get(self):
        self.render("register.html", registerForm = RegisterForm(None))

    def post(self):
        registerForm = RegisterForm(self.request.POST)

        if not registerForm.validate():
		self.render("register.html", registerForm = registerForm) 
                return

	registerForm.toModel().put()
        self.make_secure_cookie('username', registerForm.username)
        self.redirect('/posts')

class LoginHandler(Handler):
    def get(self):
        self.render("login.html", loginForm = LoginForm(None))

    def post(self):
        loginForm = LoginForm(self.request.POST)

        if not loginForm.validate():
            self.render("login.html", loginForm = loginForm)
            return

        user = User.query(User.username == loginForm.username, User.password == hmac.new(SECRET, loginForm.password).hexdigest()).get()

        if not user:
            loginForm.username_error = "Incorrect username or password"
            self.render("login.html", loginForm = loginForm)
        else:
            self.make_secure_cookie('username', user.username)
            self.redirect('/posts')

class LogoutHandler(Handler):
    def get(self):
        self.delete_cookie('username')
        self.redirect('/login')

# FORMS
class RegisterForm:
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

class LoginForm:
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

class PostForm:
    def __init__(self, post_data):

        self.title = ""
        self.content = ""
        self.post_key = ""
        self.title_error = ""
        self.content_error = ""
        
        if post_data is not None:
            self.title = post_data.get("title", "")
            self.content = post_data.get("content", "")
            self.post_key = post_data.get("post_key", "")

    def validate(self):

        valid = True
        if self.title == "":
            self.title_error = "Enter a title"
            valid = False
        if self.content == "":
            self.content_error = "Enter some content"
            valid = False

        return valid

class CommentForm:
    def __init__(self, post_data):

        self.content = "" 
        self.post = ""
        self.content_error = ""
        self.general_error = ""

        if post_data is not None:
            self.content = post_data.get("content", "")
            self.post = post_data.get("post", "")

    def validate(self):

        valid = True
        if self.content == "":
            self.content_error = "Enter a comment"
            valid = False
        if self.post == "":
            self.general_error = "A system error has occured. Please try again later"

        return valid

    def toModel(self):
        return Comment(content = self.content, post = self.post)

# MODELS
class User(ndb.Model):
    username = ndb.StringProperty(required = True)
    email = ndb.StringProperty(required = True)
    password = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    modified = ndb.DateTimeProperty(auto_now = True)

class Post(ndb.Model):
    title = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    owner = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    modified = ndb.DateTimeProperty(auto_now = True)

class Comment(ndb.Model):
    content = ndb.TextProperty(required = True)
    owner = ndb.StringProperty(required = True)
    post = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    modified = ndb.DateTimeProperty(auto_now = True)


app = webapp2.WSGIApplication([('/posts', PostListHandler), ('/post', PostHandler), ('/register', RegisterHandler), ('/login', LoginHandler), ('/logout', LogoutHandler), ('/comment', CommentHandler)], debug=True)
