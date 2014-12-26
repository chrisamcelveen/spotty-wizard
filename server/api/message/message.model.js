'use strict';

var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

var MessageSchema = new Schema({
  name: {type: String, required: true},
  message: String,
  email: String
});

module.exports = mongoose.model('Message', MessageSchema);