var jwt = require ("jwt-simple");
var parse = require ("co-body");

module.exports = function (options) {

  options = options || {};
  options.login = options.login || "/login";

  // return is authenticated
  return function * (next) {

    // @todo: if it has jwt token, honors it, it should go directly to api
    // the priority: jwt then cookie
    var login = this.path == options.login;

    // session
    this.session = this.session || {};

    // jwt
    var jot = this.query.jwt; //|| body.jwt;

    if (!jot && this.method == "POST"){
      var body = yield parse(this, { limit: '500kb' });
      jot = body.jwt;
    }

    if (jot) {
      var token = jot;
      var user = jwt.decode(token, "omama");
      this.session.user = user;
      yield next;
      return;
    }

    // now we by pass api call, be careful! -- we should have access token here
    // if this.query, or headers, the bearer yeah the bearer!!!
    if (this.session.user || this.path.indexOf("/account/login") >= 0) {

      if (login) {
        this.redirect ("/");
      } else {
        yield next;
      }

    } else {

      this.invalid = true; //it can be expired or simply a fresh request
      // @todo throw error, and push reload (if an api call)
      // this.throw (403);
      // if seeking for login page, send it to the right middleware
      if (this.path == options.login) {
        yield next;
      } else {
        
        if (this.path.indexOf("/api/") >= 0) {
          this.status = 401;
          this.body = {"error" : "invalid session"};
        } else {
          return this.redirect ( "/" + options.login);
        }

      }
    }
  };
}
