var express = require('express');
var router = express.Router();
var exec = require("child_process").exec;
var ldap = require('ldapjs');
var crypto = require('crypto');
var cfg = require('../config');
var validator = require('../inputvalidation');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Password Manager 9000' });
});

/* POST to home page. */
router.post('/', validator.validator, function(req, res, next) {
    const data = validator.escapeHtml(req.body);
    exec("PHP_AUTH_USER=\"" + data.name + "\" PHP_AUTH_PW=\"" + data.password + "\" php oc_login.php", function (error, stdout, stderr) { 
      if (error) {console.log(error);res.status(500).end("Fehler bei der Authentifizierung mit Owncloud.")}
      if(stdout){
        // LDAP Entry
        var entry = {
          objectClass: ['organizationalPerson','inetOrgPerson','top','person'],
          cn: data.name + data.surname,
          sn: data.surname,
          displayName: data.name,
          userPassword: '{SHA512}' + crypto.createHash('sha512').update(data.password).digest("base64"),
        };
        var groupEntry = new ldap.Change({
          operation: 'add',
          modification: {
            member: 'cn=' + data.name + data.surname + ',o='+ data.party+ ',dc=geofs,dc=uni-muenster,dc=de'
          }
        });
        req.client.bind(cfg.ldapAdmin, cfg.ldapPsw, function (err) {
          if (err) {console.log(err);res.status(401).end("Fehler bei der Authentifizierung mit dem Server.")}
          else{
              req.client.add('cn=' + data.name + data.surname + ',o=' + data.party+ ',dc=geofs,dc=uni-muenster,dc=de', entry, function(err) {
                if (err) {console.log(err);res.status(500).end("Error Adding User.")}
                else{
                  req.client.modify('cn=' + data.party + ',dc=geofs,dc=uni-muenster,dc=de', groupEntry, function(err) {
                    if (err) {res.status(500).end("Error adding User to Group.")}
                    else {res.status(200).end("Success.");};
                  });
                }
                });
              }});
      }else{
        // Error authenticating with OC
        res.status(401).end("Fehler beim Authentifizieren");
      }
     
    });
});
module.exports = router;
