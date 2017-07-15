const validator = require('node-validator');
const sanitizeHtml = require('sanitize-html');

const checkParams = validator.isObject()
  .withRequired('name', validator.isString({
    regex: /^(?=\w{1,50}$).+$/,
    message: 'Name musst be alphanumeric and maximum 50 characters.'
  }))
  .withRequired('surname', validator.isString({
    regex: /^(?=\w{1,50}$).+$/,
    message: 'Surname musst be alphanumeric and maximum 50 characters.'
  }))
  .withRequired('party', validator.isString({
    regex: /^(fsgi|fsgelok)$/,
    message: 'This should never happen'
  })) 
  .withRequired('password', validator.isString({
    regex: /./,
    message: 'This should never happen'
  }));

const sanitizeUserInput = function(data) {
  Object.keys(data).forEach((key) => {
    const val = data[key];
    data[key] = sanitizeHtml(val);
  });
  return data;
};

module.exports = {
  escapeHtml: sanitizeUserInput,
  validator: validator.express(checkParams),
};