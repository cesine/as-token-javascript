var config = require('./config');
var jsonwebtoken = require('jsonwebtoken');

var AsToken = {
  config: config,
  jsonwebtoken: jsonwebtoken
};

module.exports = AsToken;
