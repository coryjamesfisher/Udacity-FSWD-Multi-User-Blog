from google.appengine.ext import ndb

SECRET = "you'll never get it out of me"
ACCESS_DENIED_URL = "/login?error=1"
USER_STATIC_KEY = ndb.Key("User", "Grouping")

ERROR_DICT = {
    1: "Please authenticate to access this feature",
    2: "You are not authorized to modify this entity",
    3: "Please select a post",
    4: "Please enter a comment",
    5: "You may not like your own posts",
    6: "You do not have permission to modify this comment",
    7: "Please select a comment to delete",
    8: "Comment not found"
}
