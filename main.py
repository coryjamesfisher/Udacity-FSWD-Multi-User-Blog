import os
import jinja2
import webapp2
import hmac
import urllib
import math
from markupsafe import Markup

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


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
        self.user = username and User.query(ancestor=ndb.Key("User", "Junk")).filter(User.username == username).get()


# ENDPOINTS


class PostListHandler(Handler):
    def get(self):
        ancestor = None
        page_title = "All Posts - All Authors"

        if self.request.get("owner", ""):
            ancestor = ndb.Key(User, self.request.get("owner"))
            page_title = "All Posts - " + self.request.get("owner")

        items_per_page = 10
        page = self.request.get("page", "1")

        if not page.isdigit():
            page = 1
        else:
            page = int(page)

        offset = (page - 1) * items_per_page
        query = Post.query(ancestor=ancestor).order(-Post.created)
        posts = query.fetch(limit=10, offset=offset)
        post_count = Post.query(ancestor=ancestor).count()
        max_page = int(math.ceil(float(post_count) / items_per_page))
        self.render("list.html", posts=posts, currentPage=page, maxPage=max_page, pageTitle=page_title, owner=self.request.get("owner", ""))

class PostHandler(Handler):
    def do_create(self):

        if not self.user:
            # TODO DEFINE ERROR
            self.redirect("/posts")
            return

        post_form = PostForm(None)
        self.render("post/edit.html", postForm=post_form)

    def do_edit(self):

        if not self.request.get("post"):
            # TODO DEFINE ERROR
            self.redirect("/posts")

        post_key = ndb.Key(urlsafe=self.request.get("post"))
        post = post_key.get()

        if post.owner != self.user.username:
            # TODO DEFINE ERROR
            self.redirect("/posts")

        post_form = PostForm(None)
        post_form.title = post.title
        post_form.content = post.content
        post_form.post = self.request.get("post")

        self.render("post/edit.html", postForm=post_form)

    def do_delete(self):

        if not self.request.get("post"):
            # TODO DEFINE ERROR
            self.redirect("/posts")

        post_key = ndb.Key(urlsafe=self.request.get("post"))
        post = post_key.get()

        if post.owner != self.user.username:
            # TODO DEFINE ERROR
            self.redirect("/posts")

        post_key.delete()
        print "deleted post redirecting"
        self.redirect("/posts?owner=" + self.user.username)

    def do_view(self):

        if not self.request.get("post"):
            # TODO DEFINE ERROR
            self.redirect("/posts")

        post_key = ndb.Key(urlsafe=self.request.get("post"))
        post = post_key.get()
        comments = Comment.query(ancestor=post_key).fetch(100)

        self.render("post/view.html", post=post, comments=comments)

    def get(self):
        action = self.request.get("action", "")

        if action == 'create':
            return self.do_create()

        if action == "edit":
            return self.do_edit()

        if action == "delete":
            return self.do_delete()

        return self.do_view()

    def post(self):
        post_form = PostForm(self.request.POST)

        if not post_form.validate():
            self.render("post/edit.html", postForm=post_form)
            return

        if post_form.post:
            post_key = ndb.Key(urlsafe=self.request.get("post"))
            post = post_key.get()

            if post.owner != self.user.username:
                # todo add error message
                self.redirect('/post?post=' + post.key.urlsafe())
                return

        else:
            user_key = ndb.Key(User, self.user.username)
            post_id = ndb.Model.allocate_ids(size=1, parent=user_key)[0]
            post_key = ndb.Key(Post, post_id, parent=user_key)
            post = Post(owner=self.user.username, key=post_key)

        post.title = post_form.title
        post.content = post_form.content
        post.put()
        self.redirect('/posts?owner=' + self.user.username)
        self.redirect('/post?post=' + post_key.urlsafe())


class CommentHandler(Handler):
    def post(self):
        comment_form = CommentForm(self.request.POST)

        if not comment_form.validate():
            print "crappy error validating comment form"
            return

        comment = comment_form.to_model()
        comment.owner = self.user.username

        post_key = ndb.Key(urlsafe=comment_form.post)
        comment_id = ndb.Model.allocate_ids(size=1, parent=post_key)[0]
        comment.key = ndb.Key("Comment", comment_id, parent=post_key)

        comment.put()
        self.redirect('/post?post=' + comment_form.post)


class RegisterHandler(Handler):
    def get(self):
        self.render("register.html", registerForm=RegisterForm(None))

    def post(self):
        register_form = RegisterForm(self.request.POST)

        if not register_form.validate():
            self.render("register.html", registerForm=register_form)
            return

        register_form.to_model().put()
        self.make_secure_cookie('username', register_form.username)
        self.redirect('/posts')


class LoginHandler(Handler):
    def get(self):
        self.render("login.html", loginForm=LoginForm(None))

    def post(self):
        login_form = LoginForm(self.request.POST)

        if not login_form.validate():
            self.render("login.html", loginForm=login_form)
            return

        user = User.query(ancestor=ndb.Key("User", "Junk")).filter(
            User.username == login_form.username,
            User.password == hmac.new(SECRET, login_form.password).hexdigest()).get()

        if not user:
            login_form.username_error = "Incorrect username or password"
            self.render("login.html", loginForm=login_form)
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
        self.email = ""
        self.password = ""
        self.password_verify = ""

        if post_data is not None:
            self.username = post_data.get("username", "")
            self.email = post_data.get("email", "")
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

    def to_model(self):
        return User(username=self.username, email=self.email, password=hmac.new(SECRET, self.password).hexdigest(),
                    id=self.username, parent=ndb.Key("User", "Junk"))


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
        self.post = ""
        self.title_error = ""
        self.content_error = ""

        if post_data is not None:
            self.title = post_data.get("title", "")
            self.content = post_data.get("content", "")
            self.post = post_data.get("post", "")

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

    def to_model(self):

        # Use eventual consistency as comments could happen rapidly
        return Comment(content=self.content, post=self.post)


# MODELS
class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty(auto_now=True)


class Post(ndb.Model):
    title = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    owner = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty(auto_now=True)


class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    owner = ndb.StringProperty(required=True)
    post = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty(auto_now=True)


app = webapp2.WSGIApplication(
    [('/posts', PostListHandler), ('/post', PostHandler), ('/register', RegisterHandler), ('/login', LoginHandler),
     ('/logout', LogoutHandler), ('/comment', CommentHandler)], debug=True)
