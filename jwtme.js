var jwtme = {};
var config = require('config');
var jsonwebtoken = require('jsonwebtoken');
var _ = require('lodash');



if (!config.has('redis.host'))
	var redisHost = '127.0.0.1';
else
	var redisHost = config.get('redis.host');


if (!config.has('redis.port'))
	var redisPort = '6379';
else
	var redisHost = config.get('redis.port');



var redisClient = require("redis").createClient(redisPort, redisHost);
var EventEmitter = require('events').EventEmitter;

if (!config.has('jwtme.throttle.expiry'))
	var expiryTime = '86400';
else
	var expiryTime = config.get('jwtme.throttle.expiry');

if (!config.has('jwtme.throttle.rate'))
	var rate = 100;
else
	var rate = config.get('jwtme.throttle.rate');

var throttle = require("tokenthrottle-redis")({rate: rate, expiry: expiryTime}, redisClient);


var secret = config.get('jwtme.secret');

jwtme.create = function (payload, secret, options) {
	if(!options) {
		options = {};
	}
	options.expiresInMinutes = options.expiresInMinutes || config.get('jwtme.expiresInMinutes');
	payload.scopes = payload.scopes || [];
	return jsonwebtoken.sign(payload, secret, options);
};

jwtme.authenticate = function(req, res, next) {
	var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];

	//TODO: Add customisability to access_token
	if (!token) {
		res.status(401);
    res.json({
      "status": 401,
      "message": "Invalid credentials"
    });
    return;
	} else {
		redisClient.get(token, function(err, reply) {
			if(err) {
				console.log(err);
				return res.send(500);
			}

			if(reply) {
				res.json({
		      "status": 401,
		      "message": "Token Invalid"
		    });
			} else {
				jsonwebtoken.verify(token, secret, function(err, decoded) {
					if(err) {
						res.status(401);
				    res.json({
				      "status": 401,
				      "message": "Token Invalid"
				    });
					} else {
						if(validScope(decoded.scopes, req) || defaultScope(req)) {
							jwtme.events.emit('success', token, req.route.path)
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
		})
			
	}

	var defaultScope = function(req) {
		return _.find(config.get('jwtme.defaultscopes'), function(route) {
			return route == req.route.path;
		})
	}

	var validScope = function(scopes, req) {
		return _.find(scopes, function(scope) {
			var currScope = currentScope(config.get('jwtme.scopes'), req.route.path);
			if(currScope && currScope.name) {
				if(scope == currScope.name) {
					for(i=0; i < currScope.methods.length; i++) {
						return req.method == currScope.methods[i];
					}
				} else {
					return false;
				}
			}
		})
	}

	var currentScope = function(scopeConfig, url) {
		return _.find(scopeConfig, function(scope) {
		  return scope.route == url;
		});
	}
}

jwtme.destroy = function(token) {
	if(token != null) {
		redisClient.set(token, {is_expired: true})
		redisClient.expire(token, config.get('jwtme.expiresInMinutes')*60)
	}
}

jwtme.throttle = function(req, res, next) {
	var token = (req.body && req.body.access_token) || (req.query && req.query.access_token) || req.headers['x-access-token'];
	throttle.rateLimit(token, function(err, limited) {
		if(limited) {
			res.status(403);
			res.json({
				"status": 403,
				"message": "Rate limit exceeded, please slow down."
			})} else {
				next();
			}
	})
}

jwtme.events = new EventEmitter;

module.exports = jwtme;