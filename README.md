# phpList simpleSAML Plugin

Saml2 plugin for phpList

Bundles [SimpleSAMLphp](https://github.com/simplesamlphp/simplesamlphp) **2.4.10** and requires **PHP 8.1 or newer**.

## Plugin Setup

After `cd`-ing into the configured phpList plugin directory:

1) `git clone git@github.com:phpList/phplist-plugin-saml2.git`

## Configuration

### You can configure saml from the phplist configuration page "SSO config" category (except for certificate which should be added manually in the cert folder)
you will need to give write permission to the simplesaml/settings.php file

https://resources.phplist.com/plugin/simplesaml#simplesamlphp_installation_check

* **In [phplist-plugin-saml2/plugins/simplesaml/simplesamlphp/config/authsources.php] the following parameters will to be set:**

- **`entityID`**: The `entityID` is essentially the client ID which is specified in Keycloak or IDP
- **`idp`**: The IDP is the identifier for the IdP (Keycloak) which simplesaml would connect to.
- **`RelayState`**: The `RelayState` specifies where `simplesamlphp` should redirect to after a successful authentication. Basically it's like a callback url. This should simply be the URL from which the authentication started. Hence, a 'redirect back'.
- **`NameIDPolicy`**: The IdP is expected to return a `NameID` every successful auth session, this name ID is what identifies the user. Depending on the IdP this `NameID` might change every session. That makes it impossible to tract the user across session. So we have to said the `NameIDPolicy` to `persistent` essentially telling the IdP to send the same `NameID` all the time for the same user.

The`authsources.php` will look like (values set automatically from configuration):

```php
<?php

$config = [

   //...
   //...

   // An authentication source which can authenticate against SAML 2.0 IdPs.
   'default-sp' => [
       'saml:SP',
       // The entity ID of this SP.
       // Can be NULL/unset, in which case an entity ID is generated based on the metadata URL.
       'entityID' => 'account',
       // The entity ID of the IdP this SP should contact.
       // Can be NULL/unset, in which case the user will be shown a list of available IdPsnt.
       'idp' => 'https://sso.phplist.com:8443/realms/master',
       'baseurlpath' => 'https://saml.phplist.test/',
       'RelayState' => 'http://phplist.test/lists/admin',
       'NameIDPolicy' => [
            'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'AllowCreate' => true
        ],


   ],

   //...
   //...

];
```

- **In [phplist-plugin-saml2/plugins/simplesaml/simplesamlphp/config/config.php] the following parameters will be set:**

* **`baseurlpath`**: The `baseurlpath` refers to the base url the running `SimpleSAML` configuration. Depending on where simplesaml was installed, it could be a separate domain such as `phplist.com/simplesamlphp/public` or a path like `phplist.com/admin/simplesamlphp/public`.
(SimpleSAMLphp 2.x renamed the web root from `www` to `public`.)

_**NB:** The baseurlpath (which is essentially the simplesaml installation) is where the IdP returns the SAML response after a successful login. The SAML request would then be parsed and simplesamlphp would redirect back to the phplist url that sent the request or the one set via the `RelayState` property in the config array of `authsources.php`_ within the config dir.

The `config.php` will look like:

```php
<?php

$config = [

   //...
   //...
   'baseurlpath' => 'http://phplist.test/simplesamlphp/public/',
   //...
   //...

];
```

- **In [phplist-plugin-saml2/plugins/saml2/simplesamlphp/metadata/saml20-idp-remote.php] metadata about the IdP will be provided:**

* **Metadata array**: The metadata should be assigned to `$metadata['id']` (where id is the idp identifier passed to `idp` paramater in the config above!)
* **SingleSignOnService**: The keycloak endpoint to send login requests to.
* **SingleLogoutService**: The keycloak endpoint to send logout requests to.
* **certData**: This contains certificate information used in signing requests and verifying responses from keycloak.

**How listed meta parameters?**

More metadions may be fata optound [here]()

The `saml20-idp-remote.php` file should look like :

```php
<?php

   //...
   //...
$metadata['https://sso.phplist.com:8443/realms/master'] = [
    'SingleSignOnService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'https://sso.phplist.com:8443/realms/master/protocol/saml',
        ],
    ],
    'SingleLogoutService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'https://sso.phplist.com:8443/realms/master/protocol/saml',
        ],
    ],
    'certData' => 'CERT_STRING_',
];
```

certData will be taken from the cert/saml-remote-idp.crt file (you should add a certificate there, it will not be set from configuration page as other values are)

2) Make `phplist.domain/simplesamlphp/public` serve `PLUGIN_DIR/simplesaml/simplesamlphp/public`, and nothing else from the plugin directory

`PLUGIN_DIR` is the phpList plugin directory the plugin is installed in (e.g. `PATH_TO_PHPLIST_INSTALLATION/public_html/lists/admin/plugins`).

**Only the `public` directory may be web-accessible.** The rest of `simplesamlphp` contains the SP private key (`cert/saml-private-key.pem`), the configuration and `settings.php` (secret salt, admin password hash). Never copy or symlink the whole `simplesamlphp` directory into the web root.

## Ways to configure 2) above:

* **Apache (recommended):** deny the plugin directory, allow only `public`, and alias the URL to it:

```apache
<Directory "PLUGIN_DIR/simplesaml">
    Require all denied
    AllowOverride None
</Directory>
<Directory "PLUGIN_DIR/simplesaml/simplesamlphp/public">
    Options +FollowSymLinks
    Require all granted
    AllowOverride None
</Directory>
Alias /simplesamlphp/public PLUGIN_DIR/simplesaml/simplesamlphp/public
```

* **Apache with `.htaccess` only:** the plugin ships `simplesaml/.htaccess` (deny all) and `simplesaml/simplesamlphp/public/.htaccess` (allow). They take effect when `AllowOverride All` (or at least `AuthConfig`) is set for `PLUGIN_DIR`. You still need the URL mapping (`Alias` above, or a symlink of just the `public` directory to `PATH_TO_PHPLIST_INSTALLATION/public_html/simplesamlphp/public`).
* **nginx:** a `location ^~ /simplesamlphp/public/` pointing at `PLUGIN_DIR/simplesaml/simplesamlphp/public/` (PHP via `fastcgi_split_path_info ^(.+?\.php)(/.*)$;` so `module.php/...` paths work), plus `location ^~ PHPLIST_URL_PATH/admin/plugins/simplesaml/ { deny all; }`.

Check afterwards that `https://phplist.domain/simplesamlphp/public/module.php/saml/sp/metadata/default-sp` returns the SP metadata and that `https://phplist.domain/lists/admin/plugins/simplesaml/simplesamlphp/cert/saml-private-key.pem` returns 403/404.

SimpleSAMLphp 2.x needs a writable cache directory. It is set to `sys_get_temp_dir() . '/simplesamlphp'` via `cachedir` in `config/config.php`; change it there if your system temp dir is not writable by the web server.

**Session save path:** leave the "SAML session save path" setting empty unless you know you need it. SimpleSAMLphp keeps its own PHP session (cookie `SimpleSAML`) and switches back to phpList's session (`phpListSession`) after login, but it does not restore the save path when switching back. If the configured path differs from the one phpList uses, phpList's login is written to the wrong place and lost on the next request.

Logging goes to syslog by default (`logging.handler` in `config/config.php`). If you switch to the `file` handler, logs go to the system temp dir unless you set `loggingdir` (e.g. to `simplesamlphp/logs/`, which must then be writable by the web server).

**NB**: `simplesamlphp` **MUST BE CONFIGURED ON SAME DOMAIN** as your phplist installation. Hence `phplist.domain/simplesamlphp/public` SHOULD point to `PLUGIN_DIR/simplesaml/simplesamlphp/public`.


# UPDATING SimpleSAMLPHP [Developer Instructions]

- Download the `-slim` release tarball from https://github.com/simplesamlphp/simplesamlphp/releases (it includes `vendor/` and only the core modules, `admin`, `core` and `saml` being the ones this plugin uses; the `-full` tarball adds modules the plugin doesn't need).
- Replace `plugins/simplesaml/simplesamlphp` with it, keeping `cert/`, `config/config.php`, `config/authsources.php`, `metadata/saml20-idp-remote.php` and `public/.htaccess` (re-apply the `$settings` customizations to the new `*.dist` templates).
- No SimpleSAMLphp core files are patched; only `config/`, `metadata/` and `cert/` are phpList-specific.
- SimpleSAMLphp 2.5+ requires PHP 8.3.

## Configuring the IdP

[Keycloak](https://www.keycloak.org/) is used as the IdP in this setup. Any other IdP may be used as long as the correct configuration is set in the [simplesamlphp config](plugins/simplesaml/simplesamlphp/config) and [simplesamlphp metadata](plugins/simplesaml/simplesamlphp/metadata) directories.

### Preparing IdP Server (Keycloak)

Once keycloak server as been [installed](https://www.keycloak.org/docs/latest/server_installation/) an admin user would need to [setup](https://www.keycloak.org/docs/latest/server_admin/#creating-first-admin_server_administration_guide). With such a user, it would pe possible create/change the different configurations that would allow keycloak work with simplesamlphp. The two most important parts of the configurations are [Realms and Clients](https://www.keycloak.org/docs/latest/server_admin/#core-concepts-and-terms)

### Realms

In Keycloak, realms are used to isolate and manage a set of users, credentials, roles, and groups. A user belongs to and logs into a realm. With this in mean you can configure multiple Realms to serve different service providers, applications, organizations or whatever entity that needs to have it's own "database". That said, we do need a realm for this setup!

Keycloak does creates a `Master realm` by default but more realms can be created as seen under ["creating a realm"](https://www.keycloak.org/docs/latest/server_admin/#proc-creating-a-realm_server_administration_guide) on the keycloak documentation!

### Clients

Within the realm, there are clients! A client is an entity that can request Keycloak to authenticate a user. Most often, clients are applications and services that want to use Keycloak to secure themselves and provide a single sign-on solution. Essentially, the client represents or serves as a connector that makes request on behalf of the **service provider (in this case simplesamlphp)**

Again, we have a couple of default clients created in the `Master realm` by keycloak! Each client contains access control information such as roles and scope!

_The **account** client is used in this setup to connect keycloak simplesamlphp as it contains good defaults_

So under the clients section (https://{host.address.ext}/auth/admin/master/console/#/realms/master/clients/) of keycloak;

- Open the `account` client or the one created [as shown](https://www.keycloak.org/docs/latest/server_admin/#_client-saml-configuration) and make sure the configuration metioned below are set accordingly!

#### Client Settings/Configuration

- **Protocol**: The `Client Protocol` dropdown is set to `saml` to avoid `Wrong protocol` error.
- **Signing**: The `Sign Assertions` switch is turned on, as simplesamlphp would throw `Unhandled Exception "Neither the assertion nor the response was signed."`
- **AuthnStatement**: The `Include Authn Statement` is turned on to avoid : `Unhandled Exception "No AuthnStatement found in assertion(s)."`
- **Valid Redirect URIs**: Set the `Valid Redirect URIs` field to point to the phplist installation (with simplesamlphp plugin) for example, `saml.phplist.com` or simply `phplist.com`.

---

## Bottlenecks

- `simplesamlphp` requires at least `php-7.4`, phplist 3 accepts, `php-7.0`, `php-7.1`, `php-7.2`, `php-7.3`.

## Debugging Help

### Allow `simplesamlphp` work on unencrypted connections.

For

```bash
Fatal error:
Fatal error: Uncaught SimpleSAML\Error\CriticalConfigurationError: The configuration is invalid: Setting secure cookie on plain HTTP is not allowed. in ...
```

or

```bash
SimpleSAML\Error\CriticalConfigurationError: The configuration is invalid: Setting secure cookie on plain HTTP is not allowed.
Backtrace:
```

Change `session.cookie.secure` in `plugins/simplesaml/simplesamlphp/config.php` from `true` => `false`.

### Trusted URLS

For

```
SimpleSAML\Error\Error: UNHANDLEDEXCEPTION
Backtrace:
2 www/_include.php:17 (SimpleSAML_exception_handler)
1 vendor/symfony/error-handler/ErrorHandler.php:607 (Symfony\Component\ErrorHandler\ErrorHandler::handleException)
0 [builtin] (N/A)
Caused by: SimpleSAML\Error\Exception: URL not allowed: http://phplist.test/lists/admin/
Backtrace:
3 lib/SimpleSAML/Utils/HTTP.php:444 (SimpleSAML\Utils\HTTP::checkURLAllowed)
2 modules/saml/www/sp/saml2-acs.php:135 (require)
1 lib/SimpleSAML/Module.php:273 (SimpleSAML\Module::process)
0 www/module.php:10 (N/A)
```

Add the "not allowed" domain to the list of trusted URLs in `config.php`:

```
'trusted.url.domains' => ['phplist.test'],
```
