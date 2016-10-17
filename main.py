#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
import os
import jinja2
import hmac
import random
import string
import hashlib

from google.appengine.ext import ndb

# Hashing de senha
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
      salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    if make_pw_hash(name, pw, salt) == h:
        return True
    return False

# Criptografia de cookie
SECRET = "Meu segredo..."

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

# Jinja2 Directory Configuration
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)


# Models

class User(ndb.Model):
  username = ndb.StringProperty(required = True)
  email = ndb.StringProperty(required = True)
  password = ndb.StringProperty(required = True)
  created_at = ndb.DateTimeProperty(auto_now_add = True)



# Default Handler

class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))


# Handlers

class MainHandler(Handler):
  def get(self):
    user_id = self.request.cookies.get("user_id")
    if user_id and check_secure_val(user_id):
      self.render("index.html", logado = True)
    else:
      self.render("index.html", logado = False)


class LoginHandler(Handler):
  def get(self):
    self.render("login.html")

  def post(self):
    username = self.request.get("username")
    password = self.request.get("password")
    user = User.query(User.username == username).get()
    if user and valid_pw(username, password, user.password):
      self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(str(username)))
      self.redirect("/")
    else:
      self.render("login.html", error = True)

class SignupHandler(Handler):
  def get(self):
    self.render("signup.html")

  def post(self):
    username = self.request.get("username")
    email = self.request.get("email")
    password = self.request.get("password")
    user = User(
      username = username,
      email = email,
      password = make_pw_hash(username, password)
    )
    user.put()


app = webapp2.WSGIApplication([
  ('/', MainHandler),
  ('/login', LoginHandler),
  ('/signup', SignupHandler)
])



















