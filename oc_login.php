<?php

require_once('/srv/owncloud/lib/base.php');

if (isset($_SERVER['PHP_AUTH_USER']) 
  && OC_USER::checkPassword($_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW'])) {
  fwrite(STDOUT, 'true');
} else {
  fwrite(STDOUT, 'false');
}

?>

