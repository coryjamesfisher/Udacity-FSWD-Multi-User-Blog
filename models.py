from google.appengine.ext import ndb


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
