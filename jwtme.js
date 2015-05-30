var jwt = {};
var config = require('config');
var jsonwebtoken = require('jsonwebtoken');
var _ = require('lodash')

var secret = config.get('jwtme.secret');

jwt.create = function (payload, secret, options) {
	if(!options) {
		options = {};
	}
	options.expiresInMinutes = options.expiresInMinutes || config.get('jwtme.expiresInMinutes');
	return jsonwebtoken.sign(payload, secret, options);
};

jwt.authenticate = function(req, res, next) {
	var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];

	//TODO: Add customisability to access_token
	//TODO: Add logging for analytics
	if (!token) {
		res.status(401);
    res.json({
      "status": 401,
      "message": "Invalid credentials"
    });
    return;
	} else {
		jsonwebtoken.verify(token, secret, function(err, decoded) {
			if(err) {
				res.status(401);
		    res.json({
		      "status": 401,
		      "message": "Error decoding the token"
		    });
			} else {
				if (decoded.scopes) {
					var scopeConfig = config.get('jwtme.scopes');
					if (scopeConfig) {
						if(_.find(decoded.scopes, function(scope) {
							return scope == currentScope(scopeConfig, req.route.path);
						})) {
							next();
						} else {
							res.status(401);
					    res.json({
					      "status": 401,
					      "message": "No access to this scope"
					    });
						}
					} else {
						next();
					}
				} else {
					next();
				}
			}
		});
	}

	var currentScope = function(scopeConfig, url) {
		return _.result(_.find(scopeConfig, function(scope) {
		  return scope.route == url;
		}), 'name');
	}
}

jwt.destroy = function() {
	//TODO: Add manual revocation of the tokens
}

module.exports = jwt;