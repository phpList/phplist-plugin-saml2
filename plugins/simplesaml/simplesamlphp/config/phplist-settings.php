<?php

function simplesamlDefaultSettings(): array
{
    return [
        'simplesaml' => 'Saml',
        'hide_default_login' => false,
        'saml_idp' => 'https://sso.phplist.com:8443/realms/master',
        'saml_entity_id' => 'phplisttest',
        'saml_realm' => 'master',
        'saml_trusted_url_domains' => 'localhost',
        'saml_session_cookie_domain' => '.localhost',
        'saml_session_save_path' => '/var/lib/php/sessions',
        'saml_secret_salt' => 'defaultsecretsalt',
        'saml_admin_password' => '123',
    ];
}

function simplesamlHasConfigValue($value): bool
{
    return !($value === false || $value === null || $value === '');
}

function simplesamlBootstrapPhpList(): void
{
    if (function_exists('getConfig')) {
        return;
    }

    $documentRoot = rtrim((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''), '/');
    $candidates = [
        $documentRoot . '/lists/admin/defaultconfig.php',
        dirname(__DIR__, 4) . '/defaultconfig.php',
        dirname(__DIR__, 5) . '/admin/defaultconfig.php',
        dirname(__DIR__, 6) . '/lists/admin/defaultconfig.php',
    ];

    foreach (array_unique($candidates) as $candidate) {
        if ($candidate === '' || strpos($candidate, '//') !== false) {
            continue;
        }
        if (is_file($candidate)) {
            require_once $candidate;
        }
        if (function_exists('getConfig')) {
            return;
        }
    }
}

function simplesamlLoadSettings(): array
{
    $settings = simplesamlDefaultSettings();
    simplesamlBootstrapPhpList();

    if (!function_exists('getConfig')) {
        return $settings;
    }

    foreach ($settings as $key => $defaultValue) {
        $configured = getConfig($key);
        if (simplesamlHasConfigValue($configured)) {
            $settings[$key] = $configured;
        }
    }

    return $settings;
}
