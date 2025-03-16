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
    public $authProvider = true;
    public $description = 'Login to phpList with SAML';
    public $documentationUrl = 'https://resources.phplist.com/plugin/simplesaml';
    public $settings = [
        'simplesaml_option1' => [
            'value' => 0,
            'description' => 'Some config value',
            'type' => 'integer',
            'allowempty' => 0,
            'min' => 0,
            'max' => 999999,
            'category' => 'SSO config',
        ]
    ];

    private array $db;
    private array $config;

    function __construct()
    {
        if ( version_compare(PHP_VERSION, '7.4.0') >= 0) {
            require_once(__DIR__ . '/simplesaml/simplesamlphp/lib/_autoload.php');
        }
        parent::__construct();
        $this->db = $GLOBALS['tables'];
        $this->config = $GLOBALS['config'];
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
        $req = Sql_Fetch_Row_Query(sprintf('select loginname from %s where id = %d', $this->db['admin'], $id));

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
        $req = Sql_Fetch_Row_Query(sprintf('select email from %s where id = %d', $this->db['admin'], $id));

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
            $this->db['admin'],
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
        $req = Sql_Fetch_Row_Query(sprintf('select superuser from %s where id = %d', $this->db['admin'], $id));

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
        $req = Sql_Query("select id,loginname from {$this->db['admin']} order by loginname");
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
        $query = sprintf('select id, disabled,password from %s where id = %d', $this->db['admin'], $id);
        $data = Sql_Fetch_Row_Query($query);
        if (!$data[0]) {
            return array(0, s('No such account'));
        } elseif ($data[1]) {
            return array(0, s('your account has been disabled'));
        }

        //# do this separately from above, to avoid lock out when the DB hasn't been upgraded.
        //# so, ignore the error
        $query = sprintf('select privileges from %s where id = %d', $this->db['admin'], $id);
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
                $this->db['admin'],
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
                    $this->db['admin'],
                    addslashes($login),
                    sql_escape($email),
                    strtolower(addslashes($login)),
                    sql_escape($privileges),
                    $superuser
                ));
                $admindata = Sql_Fetch_Assoc_Query(sprintf(
                    'select loginname,password,disabled,id,superuser,privileges from %s where loginname="%s"',
                    $this->db['admin'],
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
                $this->db['admin_login'],time(),$admindata['id'],getClientIP(),"",session_id()));

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
        if (version_compare(PHP_VERSION, '7.4.0') < 0) {
            return ['PHP version 7.4 or up'  => false];
        }

        $allowEnable = false;
        if (@is_file(__DIR__).'/simplesaml/simplesamlphp/config/config.php') {
            include __DIR__.'/simplesaml/simplesamlphp/config/config.php';
            $allowEnable = $config['secretsalt'] != 'defaultsecretsalt' && $config['auth.adminpassword'] != '123';
        }

        return [
            'Simplesaml Configured' => $allowEnable,
            'phpList version 3.6.7 or later' => version_compare(VERSION, '3.6.7') >= 0,
        ];
    }
}
