<?php

require_once __DIR__ . '/../config/phplist-settings.php';
$settings = simplesamlLoadSettings();
$key = $settings['saml_idp'];

/**
 * SAML 2.0 remote IdP metadata for SimpleSAMLphp.
 *
 * Remember to remove the IdPs you don't use from this file.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-remote
 */
$metadata[$key] = [
    'SingleSignOnService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => $key . '/protocol/saml',
        ],
    ],
    'SingleLogoutService'  => $key . '/protocol/saml',
    'certData' => trim(str_replace(
        ["-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", "\n", "\r"],
        '',
        file_get_contents(__DIR__ . '/../cert/saml-remote-idp.crt')
    )),
];
