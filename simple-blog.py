import os
import re
import random
import hashlib
import hmac
from string import letters

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

SECRET = 'matt'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    #initialize is called before every request, checks to see if user is logged in
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class MainPage(BlogHandler):
    def get(self):
    	self.write('Go to /blog')

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    creator = db.StringProperty(required = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        self.btns = "<a class='edit-del' href='/blog/%s/editpost'>Edit Post</a>" % str(self.key().id())
        self.btns += "&nbsp &nbsp"
        self.btns += "<a class='edit-del' href='/blog/%s/deletepost'>Delete Post</a>" % str(self.key().id())
        self.addCom = "<form action='/blog/%s/newcomment'><input class = 'add-comment' type='submit' value='+ Comment' /></form>" % str(self.key().id())
        self.addCom += "<br>"
        return render_str("post.html", p = self)

class Comment(db.Model):
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    post = db.IntegerProperty(required = True)
    creator = db.StringProperty(required = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        self.btns = "<div class='edit-del'><a href='/blog/%s/%s/editcomment'>Edit Comment</a></div>" % (str(self.post),str(self.key().id()))
        self.btns += "&nbsp &nbsp"
        self.btns += "<a class='edit-del' href='/blog/%s/%s/deletecomment'>Delete Comment</a>" % (str(self.post),str(self.key().id()))

        return render_str("comment.html", c = self)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        comments = db.GqlQuery("SELECT * FROM Comment ORDER BY created ASC LIMIT 10")
        self.render('front.html', posts = posts, comments = comments)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and not subject.isspace() and not content.isspace():
            p = Post(parent = blog_key(), subject = subject, content = content, creator = self.user.name)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "need subject and content"
            self.render("newpost.html", subject = subject, content = content, error = error)

class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if self.user.name != post.creator:
                self.redirect('/blog')
            else:
                subject = post.subject
                content = post.content
                self.render("editpost.html", subject = subject, content = content)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and not subject.isspace() and not content.isspace():
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "need subject and content"
            self.render("editpost.html", subject = subject, content = content, error = error)

class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if self.user.name != post.creator:
                self.redirect('/blog')
            else:
                subject = post.subject
                content = post.content
                self.render("deletepost.html", post = post)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            comments = db.GqlQuery("SELECT * FROM Comment")
            for c in comments:
                if c.post == post.key().id():
                    c.delete()
                    print "comment deleted"
            post.delete()
            #db.delete(post)
            self.redirect('/blog')

class NewComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            self.render("newcomment.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        content = self.request.get('content')

        if content and not content.isspace():
            c = Comment(parent = blog_key(), content = content, post = int(post_id), creator = self.user.name)
            c.put()
            self.redirect('/blog')
        else:
            error = "need content"
            self.render("newcomment.html", content = content, error = error)

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
            comment = db.get(key)
            if not comment:
                self.error(404)
                return
            if(self.user.name != comment.creator):
                self.redirect('/blog')
            else:
                content = comment.content
                self.render("deletecomment.html", comment = comment)
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog')
        else:
            key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
            comment = db.get(key)
            comment.delete()
            #db.delete(post)
            self.redirect('/blog')

class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
            comment = db.get(key)
            if not comment:
                self.error(404)
                return
            if self.user.name != comment.creator:
                self.redirect('/blog')
            else:
                content = comment.content
                self.render("editcomment.html", content = content)
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog')

        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)
        if not comment:
            self.error(404)
            return

        content = self.request.get('content')

        if content and not content.isspace():
            comment.content = content
            comment.put()
            self.redirect('/blog')
        else:
            error = "need content"
            self.render("editpost.html", content = content, error = error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$") #'^' means match start, '$' means match end
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$") #'.' means any character but a newline
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                        email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "Not valid username"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Not valid password"
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Passwords didn't match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Not valid email"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #user can't already exist
        u = User.by_name(self.username)
        if u:
            msg = "User already exists"
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')



app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)/newcomment', NewComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/([0-9]+)/editpost', EditPost),
                               ('/blog/([0-9]+)/deletepost', DeletePost),
                               ('/blog/([0-9]+)/([0-9]+)/deletecomment', DeleteComment),
                               ('/blog/([0-9]+)/([0-9]+)/editcomment', EditComment)
                                ], 
                                debug=True)
