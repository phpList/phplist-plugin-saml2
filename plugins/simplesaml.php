<?php

require_once dirname(__FILE__, 2) . '/defaultplugin.php';
require_once __DIR__ . '/simplesaml/simplesamlphp/lib/_autoload.php';

use SimpleSAML\Auth\Simple;
use SimpleSAML\Session;
use SimpleSAML\Utils\HTTP;

class simplesaml extends phplistPlugin
{
    public $name = 'simplesaml';
    public $coderoot =  'simplesaml';
    public $version = '0.1';
    public $authors = 'Fon E. Noel Nfebe, Michiel Dethmers';
    public $enabled = 0;
    public $ssoProvider = true;
    public $authProvider = true;
    public $description = 'Login to phpList with SAML';
    public $documentationUrl = 'https://resources.phplist.com/plugin/simplesaml';
    public $autUrl = 'sso';
    public const CONFIG_CATEGORY = 'SSO config';
    public $settings = [
        'display_name' => [
            'value' => 'Saml',
            'description' => 'SSO display name',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
        'hide_default_login' => [
            'value' => false,
            'description' => 'Hide default login option',
            'type' => 'boolean',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY
        ],
        'saml_idp' => [
            'value' => 'https://sso.phplist.com:8443/realms/master',
            'description' => 'Idp of the SAML provider',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
        'saml_entity_id' => [
            'value' => 'phplisttest',
            'description' => 'SAML client id',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
        'saml_trusted_url_domains' => [
            'value' => 'localhost',
            'description' => 'SAML trusted url domains',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
        'saml_session_cookie_domain' => [
            'value' => '.localhost',
            'description' => 'SAML session cookie domains',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
        'saml_session_save_path' => [
            'value' => '/var/lib/php/sessions',
            'description' => 'SAML session save path',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
        'saml_secret_salt' => [
            'value' => 'defaultsecretsalt',
            'description' => 'Secret salt used by SimpleSAMLphp',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
        'saml_admin_password' => [
            'value' => '123',
            'description' => 'Saml admin password hash',
            'type' => 'text',
            'allowempty' => 0,
            'category' => self::CONFIG_CATEGORY,
        ],
    ];
    private const SETTINGS_FILE_NAME= 'settings.php';
    function __construct()
    {
        if ( version_compare(PHP_VERSION, '7.4.0') >= 0) {
            require_once(__DIR__ . '/simplesaml/simplesamlphp/lib/_autoload.php');
        }
        parent::__construct();
        $this->tables = $GLOBALS['tables'];
        $filename = __DIR__ . '/simplesaml/' . self::SETTINGS_FILE_NAME;
        $dataToWrite = [];
        foreach ($this->settings as $key => $setting) {
            $dataToWrite[$key] = !empty(getConfig($key)) ? getConfig($key) : $setting['value'];
        }
        $this->settings['display_name']['value'] = $dataToWrite['display_name'];

        file_put_contents($filename, "<?php\n\nreturn " . var_export($dataToWrite, true) . ";\n");
        if ($this->settings['saml_secret_salt']['value'] == getConfig('saml_secret_salt')) {
            Error($GLOBALS['I18N']->get('Please change saml secret salt').'<br/>');
        }
        if ($this->settings['saml_admin_password']['value'] == getConfig('saml_admin_password')) {
            Error($GLOBALS['I18N']->get('Please change saml admin password').'<br/>');
        }
    }

    /**
     * adminName.
     *
     * Name of the currently logged in administrator
     * Use for logging, eg "subscriber updated by XXXX"
     * and to display ownership of lists
     *
     * @param int $id ID of the admin
     *
     * @return string;
     */
    public function adminName($id)
    {
        $req = Sql_Fetch_Row_Query(sprintf('select loginname from %s where id = %d', $this->tables['admin'], $id));

        return $req[0] ? $req[0] : s('Nobody');
    }

    /**
     * adminEmail.
     *
     * Email address of the currently logged in administrator
     * used to potentially pre-fill the "From" field in a campaign
     *
     * @param int $id ID of the admin
     *
     * @return string;
     */
    public function adminEmail($id): string
    {
        $req = Sql_Fetch_Row_Query(sprintf('select email from %s where id = %d', $this->tables['admin'], $id));

        return $req[0] ? $req[0] : '';
    }

    /**
     * adminIdForEmail.
     *
     * Return matching admin ID for an email address
     * used for verifying the admin email address on a Forgot Password request
     *
     * @param string $email email address
     *
     */
    public function adminIdForEmail(string $email)
    {
        $req = Sql_Fetch_Row_Query(sprintf(
            'select id from %s where email = "%s"',
            $this->tables['admin'],
            sql_escape($email)
        ));

        return $req[0] ? $req[0] : '';
    }

    /**
     * isSuperUser.
     *
     * Return whether this admin is a super-admin or not
     *
     * @param int $id admin ID
     *
     * @return true if super-admin false if not
     */
    public function isSuperUser(int $id): bool
    {
        $req = Sql_Fetch_Row_Query(sprintf('select superuser from %s where id = %d', $this->tables['admin'], $id));

        return $req[0];
    }

    /**
     * listAdmins.
     *
     * Return array of admins in the system
     * Used in the list page to allow assigning ownership to lists
     *
     * @return array of admins
     *               id => name
     */
    public function listAdmins()
    {
        $result = array();
        $req = Sql_Query("select id,loginname from {$this->tables['admin']} order by loginname");
        while ($row = Sql_Fetch_Array($req)) {
            $result[$row['id']] = $row['loginname'];
        }

        return $result;
    }

    /**
     *
     * validateAccount, verify that the logged in admin is still valid
     *
     * this allows verification that the admin still exists and is valid
     *
     * @param int $id the ID of the admin as provided by validateLogin
     *
     * @return array
     *    index 0 -> false if failed, true if successful
     *    index 1 -> error message when validation fails
     *
     * eg
     *    return array(1,'OK'); // -> admin valid
     *    return array(0,'No such account'); // admin failed
     *
     */
    public function validateAccount($id): array
    {
        $query = sprintf('select id, disabled,password from %s where id = %d', $this->tables['admin'], $id);
        $data = Sql_Fetch_Row_Query($query);
        if (!$data[0]) {
            return array(0, s('No such account'));
        } elseif ($data[1]) {
            return array(0, s('your account has been disabled'));
        }

        //# do this separately from above, to avoid lock out when the DB hasn't been upgraded.
        //# so, ignore the error
        $query = sprintf('select privileges from %s where id = %d', $this->tables['admin'], $id);
        $req = Sql_Query($query);
        if ($req) {
            $data = Sql_Fetch_Row($req);
        } else {
            $data = array();
        }

        if (!empty($data[0])) {
            $_SESSION['privileges'] = unserialize($data[0]);
        }

        return array(1, "OK");
    }


    /**
     * login
     * called on login
     *
     * @return bool true when user is successfully logged by plugin, false instead
     */
    public function login(): bool
    {
        $as = new Simple('default-sp');
        $as->requireAuth();
        if ($as->isAuthenticated()) {
            $user = [
                "sp" => "default-sp",
                "authed" => $as->isAuthenticated(),
                "idp" => $as->getAuthData("saml:sp:IdP"),
                "nameId" => $as->getAuthData('saml:sp:NameID')->getValue(),
                "attributes" => $as->getAttributes(),
            ];
            $privileges = null;
            $login = $user['attributes']['username'][0];
            $email = $user['attributes']['email'][0];
            $superuser = 1;

            $admindata = Sql_Fetch_Assoc_Query(sprintf(
                'select loginname,password,disabled,id,superuser,privileges from %s where loginname="%s"',
                $this->tables['admin'],
                addslashes($login))
            );

            if (!$admindata) {
                if (!$privileges) {
                    $privileges = serialize([
                        'subscribers' => true,
                        'campaigns' => true,
                        'statistics' => true,
                        'settings' => true
                    ]);
                }

                $userCreated = Sql_Query(sprintf(
                    'insert into %s (loginname,email,namelc,created,privileges,superuser) values("%s","%s","%s",now(),"%s", "%d")',
                    $this->tables['admin'],
                    addslashes($login),
                    sql_escape($email),
                    strtolower(addslashes($login)),
                    sql_escape($privileges),
                    $superuser
                ));
                $admindata = Sql_Fetch_Assoc_Query(sprintf(
                    'select loginname,password,disabled,id,superuser,privileges from %s where loginname="%s"',
                    $this->tables['admin'],
                    addslashes($login)
                ));
                if ($user['nameId'] && !$userCreated || !$admindata) {
                    return false;
                }
            }

            $session = Session::getSessionFromRequest();
            $session->cleanup();

            $_SESSION['adminloggedin'] = $GLOBALS['remoteAddr'];
            $_SESSION['logindetails'] = [
                'adminname' => $login,
                'id' => $admindata['id'],
                'superuser' => $admindata['superuser']
            ];

            Sql_Query(sprintf('insert into %s (moment,adminid,remote_ip4,remote_ip6,sessionid,active) 
                values(%d,%d,"%s","%s","%s",1)',
                $this->tables['admin_login'],time(),$admindata['id'],getClientIP(),"",session_id()));

            if ($admindata['privileges']) {
                $_SESSION['privileges'] = unserialize($admindata['privileges']);
            }
            return true;
        }
        return false;
    }

    /**
     * logout
     * called on logout
     * @return null
     */
    public function logout()
    {
        $_SESSION['logindetails'] = NULL;
        $_SESSION['adminloggedin'] = NULL;

        if (isset($_SERVER['HTTP_COOKIE'])) {
            $cookies = explode(';', $_SERVER['HTTP_COOKIE']);
            foreach ($cookies as $cookie) {
                $parts = explode('=', $cookie);
                $name = trim($parts[0]);
                setcookie($name, '', time() - 1000);
                setcookie($name, '', time() - 1000, '/');
            }
        }

        session_destroy();
        HTTP::setCookie('SimpleSAMLAuthToken', '', ['expires' => time() - 3600]);
        HTTP::setCookie('AUTH_SESSION_ID', '', ['expires' => time() - 3600, 'path' => '/realms/master']);
        HTTP::setCookie('KEYCLOAK_SESSION', '', ['expires' => time() - 3600, 'path' => '/realms/master/']);
        HTTP::setCookie('KEYCLOAK_IDENTITY', '', ['expires' => time() - 3600, 'path' => '/realms/master/']);
        header('Location: ' . $_SERVER['HTTP_REFERER']);
    }

    public function dependencyCheck(): array
    {
        return ['PHP version 7.4 or up'  => version_compare(PHP_VERSION, '7.4.0') >= 0];
    }
}
