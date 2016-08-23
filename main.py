import os
import jinja2
import webapp2
import hmac
import urllib
import math
import json
import re
from markupsafe import Markup

from google.appengine.ext import ndb

# Jinja templating setup
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


# Method added as a jinja filter for urlencode.
# This is only necessary because app engine is behind on their version.
def urlencode_filter(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = s.encode('utf8')
    s = urllib.quote_plus(s)
    return Markup(s)

jinja_env.filters['urlencode'] = urlencode_filter

# CONSTANTS
SECRET = "you'll never get it out of me"
ACCESS_DENIED_URL = "/login?error=1"
USER_STATIC_KEY = ndb.Key("User", "Grouping")

ERROR_DICT = {
    1: "Please authenticate to access this feature",
    2: "You are not authorized to modify this entity",
    3: "Please select a post",
    4: "Please enter a comment",
    5: "You may not like your own posts"
}


# HANDLERS
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(dict(params, user=self.user))

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def check_secure_val(self, cookie_value):
        val = cookie_value.split('|')[0]
        if cookie_value == self.make_secure_val(val):
            return val

    def make_secure_val(self, value):
        return "%s|%s" % (value, hmac.new(SECRET, value).hexdigest())

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

        # Note: ancestor is static to allow strong consistency for users
        self.user = username and User.query(ancestor=USER_STATIC_KEY).filter(User.username == username).get()


# ENDPOINTS


class PostListHandler(Handler):
    def get(self):
        ancestor = None
        page_title = "All Posts - All Authors"

        # If there is an owner in the query string display just that
        # user's posts. Also change the title a bit.
        if self.request.get("owner", ""):
            ancestor = ndb.Key(User, self.request.get("owner"))
            page_title = "All Posts - " + self.request.get("owner")

        # Implement Paging
        items_per_page = 10
        page = self.request.get("page", "1")

        if not page.isdigit():
            page = 1
        else:
            page = int(page)

        offset = (page - 1) * items_per_page
        query = Post.query(ancestor=ancestor).order(-Post.created)
        posts = query.fetch(limit=10, offset=offset)

        # Get the total # of posts and divide by items per page for the total number of pages
        post_count = Post.query(ancestor=ancestor).count()
        max_page = int(math.ceil(float(post_count) / items_per_page))

        # Get like count using eventual consistency
        for post in posts:
            post.likeCount = Like.query(Like.post == post.key.urlsafe()).filter(Like.liked == True).count()

        # Get the posts that this user has liked.
        liked_posts = {}
        if self.user:
            liked_posts = self.user.get_likes()

        # Render error message from another page.
        error_message = ""
        if self.request.get("error"):
            error_message = ERROR_DICT[int(self.request.get("error"))]

        self.render("list.html", posts=posts, currentPage=page, maxPage=max_page,
                    pageTitle=page_title, owner=self.request.get("owner", ""), likedPosts=liked_posts,
                    errorMessage=error_message)


class PostHandler(Handler):
    def do_create(self):

        if not self.user:
            self.redirect(ACCESS_DENIED_URL)
            return

        post_form = PostForm(None)
        self.render("post/edit.html", postForm=post_form)

    def do_edit(self):

        if not self.user:
            self.redirect(ACCESS_DENIED_URL)
            return

        if not self.request.get("post"):
            self.redirect("/posts?error=3")
            return

        post_key = ndb.Key(urlsafe=self.request.get("post"))
        post = post_key.get()

        if post.owner != self.user.username:
            self.redirect("/posts?error=2")
            return

        post_form = PostForm(None)
        post_form.title = post.title
        post_form.content = post.content
        post_form.post = self.request.get("post")

        self.render("post/edit.html", postForm=post_form)

    def do_delete(self):

        if not self.user:
            self.redirect(ACCESS_DENIED_URL)
            return

        if not self.request.get("post"):
            self.redirect("/posts?error=3")
            return

        post_key = ndb.Key(urlsafe=self.request.get("post"))
        post = post_key.get()

        if post.owner != self.user.username:
            self.redirect("/posts?error=2")
            return

        post_key.delete()

        self.redirect("/posts?owner=" + self.user.username)

    def do_view(self):

        if not self.request.get("post"):
            self.redirect("/posts?error=3")
            return

        # Get the post
        post_key = ndb.Key(urlsafe=self.request.get("post"))
        post = post_key.get()

        # Get comments for the post
        comments = Comment.query(ancestor=post_key).fetch(100)

        # See if the user liked this post.
        liked_posts = {}
        if Like.query(Like.owner == self.user.username and
           Like.post == post_key.urlsafe()).filter(Like.liked == True).get():
            liked_posts[post_key.urlsafe()] = True

        # Get like count for the post
        post.likeCount = Like.query(Like.post == post_key.urlsafe()).filter(Like.liked == True).count()
        self.render("post/view.html", post=post, comments=comments, likedPosts=liked_posts)

    def get(self):

        # This method is a hub for all of the individual post related actions
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

        if not self.user:
            self.redirect(ACCESS_DENIED_URL)
            return

        if not post_form.validate():
            self.render("post/edit.html", postForm=post_form)
            return

        # Existing post
        if post_form.post:
            post_key = ndb.Key(urlsafe=self.request.get("post"))
            post = post_key.get()

            # If this user doesn't own the post they can't modify it
            if post.owner != self.user.username:
                self.redirect('/post?post=' + post.key.urlsafe() + '&error=2')
                return

        else:

            # New post
            user_key = ndb.Key(User, self.user.username)
            post_id = ndb.Model.allocate_ids(size=1, parent=user_key)[0]
            post_key = ndb.Key(Post, post_id, parent=user_key)
            post = Post(owner=self.user.username, key=post_key)

        # Whether new or existing update title and content
        post.title = post_form.title
        post.content = post_form.content

        post.put()

        self.redirect('/post?post=' + post_key.urlsafe())


class CommentHandler(Handler):
    def post(self):
        comment_form = CommentForm(self.request.POST)

        if not self.user:
            self.redirect(ACCESS_DENIED_URL)
            return

        if not comment_form.validate():
            self.redirect("/post?post=" + comment_form.post + "&error=4")
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

        error_message = ""
        if self.request.get("error"):
            error_message = ERROR_DICT[int(self.request.get("error"))]

        self.render("login.html", loginForm=LoginForm(None), errorMessage=error_message)

    def post(self):
        login_form = LoginForm(self.request.POST)

        if not login_form.validate():
            self.render("login.html", loginForm=login_form)
            return

        user = User.query(ancestor=USER_STATIC_KEY).filter(
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


class LikeHandler(Handler):
    def post(self):

        # Respond to ajax with json
        self.response.headers['Content-Type'] = 'application/json'

        # Make sure the post exists
        post = ndb.Key(urlsafe=self.request.get('post')).get()

        error = False
        if not self.user:
            error = ERROR_DICT[1]
        if not post:
            error = ERROR_DICT[3]
        elif post.owner == self.user.username:
            error = ERROR_DICT[5]

        if error:
            self.response.out.write(json.dumps({"error": error}))
            return

        # Get the like key based on post & username.
        like_key = ndb.Key(Like, self.user.username + "|" + self.request.get('post'))
        like = like_key.get()

        # If no record create one. Otherwise just toggle the liked property.
        if not like:
            like = Like(owner=self.user.username, post=self.request.get('post'), liked=True, key=like_key)
        elif like.liked is True:
            like.liked = False
        else:
            like.liked = True

        like.put()
        self.response.out.write(json.dumps({"success": True}))


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
        elif ndb.Key(User, self.username, parent=USER_STATIC_KEY).get():
            self.username_error = "Username is taken"
            valid = False

        if self.email == "" or not re.match(r"[^@]+@[^@]+\.[^@]+", self.email):
            self.email_error = "Enter an email in the right format"
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
                    id=self.username, parent=USER_STATIC_KEY)


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
            self.general_error = "A system error has occurred. Please try again later"

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

    def get_likes(self):

        liked_posts = {}
        all_likes = Like.query(Like.owner == self.username).fetch()
        for like in all_likes:

            if like.liked is True:
                liked_posts[like.post] = True

        return liked_posts


class Post(ndb.Model):

    # Like count managed outside of the model for eventual consistency
    likeCount = 0

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


class Like(ndb.Model):
    owner = ndb.StringProperty(required=True)
    post = ndb.StringProperty(required=True)
    liked = ndb.BooleanProperty(required=True)


app = webapp2.WSGIApplication(
    [('/', PostListHandler), ('/posts', PostListHandler), ('/post', PostHandler),
     ('/register', RegisterHandler), ('/login', LoginHandler), ('/logout', LogoutHandler),
     ('/comment', CommentHandler), ('/like', LikeHandler)], debug=True)
