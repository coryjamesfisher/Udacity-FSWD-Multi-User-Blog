import os
import jinja2
import webapp2
import hmac
import urllib
import math
import json
from markupsafe import Markup
from google.appengine.ext import ndb
from forms import RegisterForm, LoginForm, PostForm, CommentForm
from models import User, Post, Comment, Like
from globals import *

# Jinja templating setup
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Method added as a jinja filter for urlencode.
# This is only necessary because app engine is behind on their version.
def urlencode_filter(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = s.encode('utf8')
    s = urllib.quote_plus(s)
    return Markup(s)

jinja_env.filters['urlencode'] = urlencode_filter


class Handler(webapp2.RequestHandler):
    """Base handler which all other handlers extend from"""

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
        """This method is called when the object is created"""

        webapp2.RequestHandler.initialize(self, *a, **kw)

        # Use this as an opportunity to see if the user is authenticated
        username = self.read_secure_cookie('username')

        # Note: ancestor is static to allow strong consistency for users
        self.user = username and \
            User.query(ancestor=USER_STATIC_KEY)\
                .filter(User.username == username).get()


class PostListHandler(Handler):
    """Handler for listing posts"""

    def get(self):
        """
        Gets all posts optionally filtered by owner and
        ordered by created datetime desc"""

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

        # Get the total # of posts and divide by items per page
        # yielding the total number of pages
        post_count = Post.query(ancestor=ancestor).count()
        max_page = int(math.ceil(float(post_count) / items_per_page))

        # Get like count using eventual consistency
        for post in posts:
            post.likeCount = Like.query(Like.post == post.key.urlsafe())\
                .filter(Like.liked == True).count()

        # Get the posts that this user has liked.
        liked_posts = {}
        if self.user:
            liked_posts = self.user.get_likes()

        # Render error message from another page.
        error_message = ""
        if self.request.get("error"):
            error_message = ERROR_DICT[int(self.request.get("error"))]

        self.render("list.html", posts=posts, currentPage=page,
                    maxPage=max_page, pageTitle=page_title,
                    owner=self.request.get("owner", ""),
                    likedPosts=liked_posts,
                    errorMessage=error_message)


class PostHandler(Handler):
    """Handler for single post related actions"""

    def do_create(self):
        """Shows the create post form"""

        if not self.user:
            self.redirect(ACCESS_DENIED_URL)
            return

        post_form = PostForm(None)
        self.render("post/edit.html", postForm=post_form)

    def do_edit(self):
        """Edit an existing post"""

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
        """Delete a post"""

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
        """View a post"""

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
        post.likeCount = Like.query(Like.post == post_key.urlsafe())\
            .filter(Like.liked == True).count()
        self.render("post/view.html", post=post, comments=comments,
                    likedPosts=liked_posts)

    def get(self):
        """
        This method is a hub for all of the individual post related actions"""

        action = self.request.get("action", "")

        if action == 'create':
            return self.do_create()

        if action == "edit":
            return self.do_edit()

        if action == "delete":
            return self.do_delete()

        return self.do_view()

    def post(self):
        """Handle modification/creation of a post"""

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
    """Handler for comment related actions"""

    def post(self):
        """
        Handle creating or updating a comment
        returns:
            json"""

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
    """Handler for user registration actions"""

    def get(self):
        """Render the user registration form"""

        self.render("register.html", registerForm=RegisterForm(None))

    def post(self):
        """Handle user registration form submission"""

        register_form = RegisterForm(self.request.POST)

        if not register_form.validate():
            self.render("register.html", registerForm=register_form)
            return

        register_form.to_model().put()
        self.make_secure_cookie('username', register_form.username)
        self.redirect('/posts')


class LoginHandler(Handler):
    """Handler for login actions"""

    def get(self):
        """Render the login form"""

        error_message = ""
        if self.request.get("error"):
            error_message = ERROR_DICT[int(self.request.get("error"))]

        self.render("login.html", loginForm=LoginForm(None),
                    errorMessage=error_message)

    def post(self):
        """Handle login form submission"""

        login_form = LoginForm(self.request.POST)

        if not login_form.validate():
            self.render("login.html", loginForm=login_form)
            return

        user = User.query(ancestor=USER_STATIC_KEY).filter(
            User.username == login_form.username,
            User.password == hmac
                .new(SECRET, login_form.password).hexdigest()).get()

        if not user:
            login_form.username_error = "Incorrect username or password"
            self.render("login.html", loginForm=login_form)
        else:
            self.make_secure_cookie('username', user.username)
            self.redirect('/posts')


class LogoutHandler(Handler):
    """Handler for logout action"""

    def get(self):
        self.delete_cookie('username')
        self.redirect('/login')


class LikeHandler(Handler):
    """Handler for liking/unlinking posts"""

    def post(self):
        """
        This method will toggle a post between liked and unliked
        states for a user
        Outputs:
            json
        """

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
        like_key = ndb.Key(Like,
                           self.user.username + "|" + self.request.get('post'))
        like = like_key.get()

        # If no record create one. Otherwise just toggle the liked property.
        if not like:
            like = Like(owner=self.user.username,
                        post=self.request.get('post'),
                        liked=True, key=like_key)
        elif like.liked is True:
            like.liked = False
        else:
            like.liked = True

        like.put()
        self.response.out.write(json.dumps({"success": True}))


app = webapp2.WSGIApplication(
    [('/', PostListHandler), ('/posts', PostListHandler),
     ('/post', PostHandler), ('/register', RegisterHandler),
     ('/login', LoginHandler), ('/logout', LogoutHandler),
     ('/comment', CommentHandler), ('/like', LikeHandler)], debug=True)
