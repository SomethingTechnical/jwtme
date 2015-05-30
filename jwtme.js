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
	payload.scopes = payload.scopes || [];
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
				if(validScope(decoded.scopes, req) || defaultScope(req)) {
					next();
				} else {
					res.status(401);
			    res.json({
			      "status": 401,
			      "message": "No Access to this scope"
			    });
				}
			}
		});
	}

	var defaultScope = function(req) {
		return _.find(config.get('jwtme.defaultscopes'), function(route) {
			return route == req.route.path;
		})
	}

	var validScope = function(scopes, req) {
		return _.find(scopes, function(scope) {
			var currScope = currentScope(config.get('jwtme.scopes'), req.route.path);
			if(scope == currScope.name) {
				for(i=0; i < currScope.methods.length; i++) {
					return req.method == currScope.methods[i];
				}
			} else {
				return false;
			}
		})
	}

	var currentScope = function(scopeConfig, url) {
		return _.find(scopeConfig, function(scope) {
		  return scope.route == url;
		});
	}
}

jwt.destroy = function() {
	//TODO: Add manual revocation of the tokens
}

module.exports = jwt;