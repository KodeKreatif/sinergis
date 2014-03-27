module.exports = function (options) {

  options = options || {};
  options.login = options.login || "/login";

  // return is authenticated
  return function * (next) {

    // @todo: if it has jwt token, honors it, it should go directly to api
    // the priority: jwt then cookie

    var login = this.path == options.login;

    if (this.session.user) {

      if (login) {
        
        // get app root
        this.redirect ("/");

      } else {
        
        // @todo: check session's validity
        yield next;
      }

    } else {

      this.invalid = true; //it can be expired or simply a fresh request

      // @todo throw error, and push reload (if an api call)
      // this.throw (403);

      var anonymous = false;
      if (options.app && options.app.anonymousPaths) {
        var anonymousPaths = options.app.anonymousPaths;
        for (var i = 0; i < anonymousPaths.length; i ++) {
          if (this.path.substr(0, anonymousPaths[i].length) == anonymousPaths[i]) {
            anonymous = true;
            break;
          }
        }
      }
      // if seeking for login page, send it to the right middleware
      // Also applies to anonymous pages
      if (this.path == options.login || anonymous) {
        yield next;
      } else {
        // since this request doesn't have a valid session, then send it to login handler
        this.redirect (options.login);  
      }
    }
  };
}
