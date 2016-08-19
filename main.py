import os
import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# ENDPOINTS
class PostHandler(Handler):
    def get(self):
        posts = [{"title": "Why is cory so cool? <marquee>HAHAHA</marquee>"}, {"title": "Cory Is So Awesome!"}]
        self.render("list.html", coolname="CORY", posts=posts)

class UserHandler(Handler):
    def get(self):
        self.render("register.html", userForm = UserForm(None))

    def post(self):
        userForm = UserForm(self.request.POST))

        # or not userService.register(userForm)
        if userForm.username == "" or userForm.email == "" or userForm.password == "" or userForm.verify_password == "":
		self.render("register.html", userForm = userForm) 

        # self
        self.redirect('/posts')

class AuthHandler(Handler):
    def get(self):
        self.render("auth.html", authForm = AuthForm(None))

    def post(self):
        authForm = AuthForm(self.request.POST)

        # or not authService.authenticate(authForm)
        if authForm.username == "" or authForm.password == "":
            self.render("auth.html", authForm = authForm)
        else:
            self.redirect('/posts')

# FORMS
class UserForm:
    def __init__(self, post_data):

        if post_data is not None:
            self.username = post_data.get("username", "")
            self.email    = post_data.get("email", "")
        else:
            self.username = ""
            self.password = ""

class AuthForm:
    def __init__(self, post_data):

        if post_data is not None:
            self.username = post_data.get("username", "")
            self.password = post_data.get("password", "")
        else:
            self.username = ""
            self.password = ""

app = webapp2.WSGIApplication([('/posts', PostHandler), ('/users', UserHandler), ('/auth', AuthHandler)], debug=True)
