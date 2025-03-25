<?php

return array (
  'display_name' => 'Saml',
  'hide_default_login' => false,
  'saml_idp' => 'https://sso.phplist.com:8443/realms/master',
  'saml_entity_id' => 'phplisttest',
  'saml_trusted_url_domains' => 'localhost',
  'saml_session_cookie_domain' => '.localhost',
  'saml_session_save_path' => '/var/lib/php/sessions',
  'saml_secret_salt' => 'defaultsecretsalt',
  'saml_admin_password' => '1234',
);
