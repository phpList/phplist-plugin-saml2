<?php

return array (
  'display_name' => 'Saml',
  'hide_default_login' => false,
  'saml_idp' => 'https://sso.phplist.com:8443/realms/master',
  'saml_entity_id' => 'phplisttest',
  'saml_trusted_url_domains' => 'localhost',
  'saml_session_cookie_domain' => '.localhost',
  'saml_session_savepath' => '/var/lib/php/sessions',
);
