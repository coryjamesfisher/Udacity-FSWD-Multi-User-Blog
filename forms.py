from models import User, Comment
import re
import hmac
from globals import *


class RegisterForm:
    """Form for user registration"""

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
        return User(username=self.username,
                    email=self.email,
                    password=hmac.new(SECRET, self.password).hexdigest(),
                    id=self.username, parent=USER_STATIC_KEY)


class LoginForm:
    """Form for user login"""

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
    """Form for creating/editing posts"""

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
    """Form for creating/editing comments"""

    def __init__(self, post_data):

        self.content = ""
        self.post = ""
        self.comment = ""

        self.content_error = ""
        self.general_error = ""

        if post_data is not None:
            self.content = post_data.get("content", "")
            self.post = post_data.get("post", "")
            self.comment = post_data.get("comment", "")

    def validate(self):

        valid = True
        if self.content == "":
            self.content_error = "Enter a comment"
            valid = False
        if self.post == "":
            self.general_error = \
                "A system error has occurred. Please try again later"

        return valid

    def to_model(self):

        # Here we use eventual consistency as comments could happen rapidly
        # First case is modification of existing comment
        if self.comment:
            comment = ndb.Key(urlsafe=self.comment).get()
            comment.content = self.content
            return comment

        # New comment
        return Comment(content=self.content, post=self.post)
