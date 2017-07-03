var express = require('express');
var router = express.Router();
var exec = require("child_process").exec;
var ldap = require('ldapjs');
var crypto = require('crypto');

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
          cn: req.body.name + req.body.surname,
          sn: req.body.surname,
          displayName: req.body.name,
          userPassword: '{SHA512}' + crypto.createHash('sha512').update(req.body.password).digest("hex"),
          objectclass: 'inetOrgPerson',
          objectclass: 'organizationalPerson',
          objectclass: 'person',
          objectclass: 'top',
        };
        var groupEntry = new ldap.Change({
          operation: 'add',
          modification: {
            member: 'cn=' + req.body.name + req.body.surname + ',o='+ req.body.party+ ',dc=geofs,dc=uni-muenster,dc=de'
          }
        });
        req.client.add('cn=' + req.body.name + req.body.surname + ',o='+ req.body.party+ ',dc=geofs,dc=uni-muenster,dc=de', entry, function(err) {
          res.status(500).end("Error Adding User.");
        });
        req.client.modify('cn=' + req.body.party + ',dc=geofs,dc=uni-muenster,dc=de', groupEntry, function(err) {
          res.status(500).end("Error adding User to Group.");
        });
        res.status(200).end("Success authenticating.");
      }else{
        // Error authenticating with OC
        res.status(401).end("Fehler beim Authentifizieren");
      }
     
    });
});
module.exports = router;
