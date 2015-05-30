var express = require('express');
var app = express();
var jwtme = require('./jwtme');
var config = require('config');


var secret = config.get('jwtme.secret');

app.get('/', jwtme.authenticate, function (req, res) {
  res.send('Hello World!');
});

app.get('/users', jwtme.authenticate, function (req, res) {
  res.send('Hello World!');
});

var server = app.listen(3000, "127.0.0.1", function () {

  var host = server.address().address;
  var port = server.address().port;
  console.log(jwtme.create({user: "lol"}, secret));
  console.log('Example app listening at http://%s:%s', host, port);
});