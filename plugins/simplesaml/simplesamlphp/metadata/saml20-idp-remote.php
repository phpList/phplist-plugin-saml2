<?php

/**
 * SAML 2.0 remote IdP metadata for SimpleSAMLphp.
 *
 * Remember to remove the IdPs you don't use from this file.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-remote
 */
$metadata['https://sso.phplist.com:8443/realms/master'] = [
    'SingleSignOnService'  => 'https://sso.phplist.com:8443/realms/master/protocol/saml',
    'SingleLogoutService'  => 'https://sso.phplist.com:8443/realms/master/protocol/saml',
    'SingleSignOnService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'https://sso.phplist.com:8443/realms/master/protocol/saml',
        ],
    ],
    'SingleLogoutService'  => 'https://sso.phplist.com:8443/realms/master/protocol/saml',
    'certData' => 'MIICmzCCAYMCBgGT+ZELyzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQxMjI0MTY0NTUyWhcNMzQxMjI0MTY0NzMyWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQw7+3fpK1RK3j5pN0/oqM/fuvR6u/zRUOlN/LYYvMkmMzG+OoIYybp76qDDqw/6JV6jmSReobmXUX/+97N2gvIrjBIhZG4XXB1qlLJBwkZKXxbu0bRh9Ag0wZuZHHNaB4fByynHvihNnVDzVcICfQybj2Ry8LuDZPo7bnp5zKi++Dz/VxutdA39gRzsv7L5/FZQHNCdxSB59YsGCcMgzxRfgePMw3KLwCHUMzXzusruXr9K3EaosG5cpKQZJYxxRQxDuOZc/HAuP5/y0dHKOO9vftUOgbo2AFi0Eo4OD+moTIiEHgfptXds0vT5s/M3Ql4K++xLIDHkvVPzOjApl7AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABr73c78puB8X3+Kebta+A4qhGSB66OVkssZ8XjKLx3bhl0dzoarj5PJmJhvt6i6FxcVJtCqHHhLAp/pHRkLymjkmm46vhV6C73C/0T8tp+57hxVJoCrIINxlMy63AVF6uxk9r7T7fAjPVSNvvgomS8VjMWosLuKVrt94aiZNz60su+ZwPWVk0chEPgTDuu/+dHG7rF5GBr6uzAIaFx78NIDug2AXbDx99YdfjFIocvdvgQdWF0Z2PZjI/OhxtJEITNXaAC1HE51jYAemExp7OYkmtSym9eI5xCedyVZHdjCJbvuLeb6vtq/08NpY6VVdrmk+QVtsssaw7vwHU/kWfE=',
];
