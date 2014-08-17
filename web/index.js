/**
 * Module dependencies.
 */
var render = require ("./lib/render");
var compose = require ("koa-compose");
var Router = require ("koa-router");
var thunkify = require ("thunkify");
var door = require ("./lib/door");
var auth = require ("./lib/auth");
var jwt = require ("jwt-simple");
var parse = require ("co-body");
var path = require ("path");
var fs = require ("fs");

module.exports = function (policy) {

  policy = policy || {};

  var router = new Router();
  var app = policy.app || {};
  var dir = app.path + "/views";
  var login = policy.login ? (path.extname (policy.login) ? policy.login : (policy.login + ".html")) : "login.html";
  var overridden = fs.existsSync (dir + "/" + login);
  var authenticate = thunkify(auth);

  router.get("/login", function * (next) {
    this.session = this.session || {};
    if (this.session.user) {
      this.redirect("/");
    } else {
      if (overridden) {
        var error = this.session.error;
        this.body = yield render(dir)("login", { error : error, csrf : this.csrf });
        delete this.session.error;
      } else {
        this.body = yield render()("index");
      }
    }
  });

  router.post("/login", function * (next) {

    try {
      // @todo: check to database via user model, user model can fetch the data directly from db or api
      var body = yield parse(this, { limit: '1kb' });
      this.assertCSRF(body);
      var options = {
        username : body.username,
        password : body.password,
        client : body.client,
        policy : policy,
        mock : false
      }

      var user = yield authenticate(options);

      if (user) {
        this.session = this.session || {};
        this.session.user = user;
        this.session.ip = this.ip;
        this.session.ips = this.ips;
        // this.session.jwt =
        // this.session.sid =
        // this.redirect("/");
        this.redirect("/");

      } else {
        this.redirect("/login");
      }

    } catch (err) {
      this.session = { error : err };
      this.redirect("/login");
    }
  });

  router.all("/logout", function * (next) {
    this.session = {};
    this.redirect("/login");
  });

  return compose ([router.middleware(), door(policy)]);
}
