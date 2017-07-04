var express = require('express');
var router = express.Router();
var exec = require("child_process").exec;
var ldap = require('ldapjs');
var crypto = require('crypto');
var cfg = require('../config');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Password Manager 9000' });
});

/* POST to home page. */
router.post('/', function(req, res, next) {
    exec("PHP_AUTH_USER=\"" + req.body.name + "\" PHP_AUTH_PW=\"" + req.body.password + "\" php oc_login.php", function (error, stdout, stderr) { 
      if(stdout){
        // LDAP Entry
        var entry = {
          objectClass: ['organizationalPerson','inetOrgPerson','top','person'],
          cn: req.body.name + req.body.surname,
          sn: req.body.surname,
          displayName: req.body.name,
          userPassword: '{SHA512}' + crypto.createHash('sha512').update(req.body.password).digest("base64"),
        };
        var groupEntry = new ldap.Change({
          operation: 'add',
          modification: {
            member: 'cn=' + req.body.name + req.body.surname + ',o='+ req.body.party+ ',dc=geofs,dc=uni-muenster,dc=de'
          }
        });
        req.client.bind(cfg.ldapAdmin, cfg.ldapPsw, function (err) {
          if (err) {console.log(err);res.status(401).end("Fehler bei der Authentifizierung mit dem Server.")}
          else{
            console.log('o=' + req.body.party+ ',dc=geofs,dc=uni-muenster,dc=de');
            req.client.add('cn=' + req.body.name + req.body.surname + ',o=' + req.body.party+ ',dc=geofs,dc=uni-muenster,dc=de', entry, function(err) {
              if (err) {console.log(err);res.status(500).end("Error Adding User.")}
              else{
                req.client.modify('cn=' + req.body.party + ',dc=geofs,dc=uni-muenster,dc=de', groupEntry, function(err) {
                  if (err) {res.status(500).end("Error adding User to Group.")}
                  else {res.status(200).end("Success.");};
                });
              }
            });
          }
        });  
      }else{
        // Error authenticating with OC
        res.status(401).end("Fehler beim Authentifizieren");
      }
     
    });
});
module.exports = router;
