<?php
/**               -JMJ-
 *
 * Tiny Tiny RSS plugin for FreeIPA authentication
 *
 * @author stonewall
 * @license https://opensource.org/licenses/MIT
 * @version 0.01
 *
 * This plugin authenticates users within the local FreeIPA domain.
 *
 * It provides both "Single Sign-On" capability through integration with a
 * GSSAPI/Kerberos-enabled webserver, as well as standard authentication using
 * LDAP binds against the domain LDAP servers.
 *
 * This plugin requires php-ldap compiled with SASL support, along with
 * accessible kerberos credentials. Check the README for more information.
 *
 * The following options may be specified in config.php:
 *
 *   // Optional overrides. If unspecified, autodiscovery will be used.
 *   putenv('TTRSS_AUTH_FREEIPA_DOMIN=ipa.example.com');
 *   putenv('TTRSS_AUTH_FREEIPA_REALM=IPA.EXAMPLE.COM');
 *   putenv('TTRSS_AUTH_FREEIPA_LDAP_URI=ldap://freeipa1.ipa.example.com');
 *   putenv('TTRSS_AUTH_FREEIPA_BASEDN=dc=ipa,dc=example,dc=com');
 *
 *   // If specified, access is only granted to members of at least one of the
 *   // provided groups. Takes a list of group names.
 *   putenv('TTRSS_AUTH_FREEIPA_ALLOW_GROUPS=ttrss_users,rss_fans');
 *
 *   // If specified, admin privileges are granted to members of at least one of
 *   // the provided groups. Takes a list of group names. Changes are only applied
 *   // on login.
 *   putenv('TTRSS_AUTH_FREEIPA_ADMIN_GROUPS=ttrss_admins,sysadmins');
 */

class Auth_Freeipa extends Auth_Base {

  const AUTH_FREEIPA_DOMAIN       = 'AUTH_FREEIPA_DOMAIN';
  const AUTH_FREEIPA_REALM        = 'AUTH_FREEIPA_REALM';
  const AUTH_FREEIPA_LDAP_URI     = 'AUTH_FREEIPA_LDAP_URI';
  const AUTH_FREEIPA_BASEDN       = 'AUTH_FREEIPA_BASEDN';
  const AUTH_FREEIPA_ALLOW_GROUPS = 'AUTH_FREEIPA_ALLOW_GROUPS';
  const AUTH_FREEIPA_ADMIN_GROUPS = 'AUTH_FREEIPA_ADMIN_GROUPS';

  private $domain;
  private $realm;
  private $basedn;
  private $ldap_uri;
  private $ldapconn;
  private $ready = false;

  function about() {
    return array(null,
      'Authenticates against local FreeIPA domain',
      'stonewall@sacredheartsc.com',
      true);
  }

  function init($host) {
    $host->add_hook($host::HOOK_AUTH_USER, $this);

    Config::add(self::AUTH_FREEIPA_DOMAIN,       '', Config::T_STRING);
    Config::add(self::AUTH_FREEIPA_REALM,        '', Config::T_STRING);
    Config::add(self::AUTH_FREEIPA_LDAP_URI,     '', Config::T_STRING);
    Config::add(self::AUTH_FREEIPA_BASEDN,       '', Config::T_STRING);
    Config::add(self::AUTH_FREEIPA_ALLOW_GROUPS, '', Config::T_STRING);
    Config::add(self::AUTH_FREEIPA_ADMIN_GROUPS, '', Config::T_STRING);
  }

  private function log($msg, $level = E_USER_NOTICE) {
    Logger::log($level, $msg);
  }

  private function discover_dns_domain() {
    if ($local_fqdn = gethostbyaddr(gethostbyname(gethostname()))) {
      $domain = strtolower(explode('.', $local_fqdn, 2)[1]);
      if (!in_array($domain, [$local_fqdn, 'localhost', 'localdomain', 'localhost.localdomain'])) {
        $this->domain = $domain;
        return true;
      }
    }
    return false;
  }

  private function discover_kerberos_realm() {
    if ($kerberos_txt_record = dns_get_record("_kerberos.{$this->domain}", DNS_TXT)) {
      $this->realm = $kerberos_txt_record[0]['txt'];
      return true;
    }
    return false;
  }

  private function discover_ldap_servers() {
    if ($ldap_srv_records = dns_get_record("_ldap._tcp.{$this->domain}", DNS_SRV)) {
      foreach ($ldap_srv_records as $record) {
        $ldap_uris[] = "ldap://$record[target]:$record[port]";
      }
      $this->ldap_uri = implode(' ', $ldap_uris);
      return true;
    }
    return false;
  }

  private function discover_basedn() {
    $results = ldap_read($this->ldapconn, '', 'objectClass=*', ['defaultnamingcontext']);
    if ($results && ldap_count_entries($this->ldapconn, $results) == 1) {
      if ($root_dse = ldap_first_entry($this->ldapconn, $results)) {
        $attributes = ldap_get_attributes($this->ldapconn, $root_dse);
        if ($attributes['defaultnamingcontext']['count'] == 1) {
          $this->basedn = $attributes['defaultnamingcontext'][0];
          return true;
        }
      }
    }
    return false;
  }

  private function guess_basedn_from_realm() {
    $this->basedn = implode(',', preg_filter('/^/', 'dc=', explode('.', strtolower($this->realm))));
  }

  private function userdn($username) {
    return 'uid=' . ldap_escape($username) . ",cn=users,cn=accounts,{$this->basedn}";
  }

  private function groupdn($groupname) {
    return 'cn=' . ldap_escape($groupname) . ",cn=groups,cn=accounts,{$this->basedn}";
  }

  private function authenticate_via_ldap($username, $password) {
    return ldap_bind($this->ldapconn, $this->userdn($username), $password);
  }

  private function authenticate_via_remote() {
    if (isset($_SERVER['REMOTE_USER'])) {
      $remote_user = explode('@', $_SERVER['REMOTE_USER'], 2);
      if (count($remote_user) == 2 && $remote_user[1] != $this->realm) {
        $this->log("Denied user from unknown realm {$remote_user[1]}, check your kerberos configuration", E_USER_WARNING);
        return false;
      }
      return $remote_user[0];
    }
    return false;
  }

  private function ldap_get_user($username, $filter = null) {
    if (empty($filter)) {
      $filter = 'objectClass=*';
    }

    $results = ldap_read($this->ldapconn, $this->userdn($username), $filter, ['displayName', 'mail', 'memberOf']);
    if ($results && ldap_count_entries($this->ldapconn, $results) == 1) {
      if ($entry = ldap_first_entry($this->ldapconn, $results)) {
        return ldap_get_attributes($this->ldapconn, $entry);
      }
    }
    return false;
  }

  private function _init() {
    if ($this->ready) {
      return true;
    }

    if (!function_exists('ldap_connect')) {
      $this->log('auth_freeipa requires php-ldap, and it is not installed'. E_USER_ERROR);
      return false;
    }

    // get local domain
    if (!empty(Config::get(self::AUTH_FREEIPA_DOMAIN))) {
      $this->domain = Config::get(self::AUTH_FREEIPA_DOMAIN);
    } elseif (!$this->discover_dns_domain()) {
      $this->log("Failed to discover local domain. Try setting " . self::AUTH_FREEIPA_DOMAIN, E_USER_ERROR);
      return false;
    }

    // get local realm
    if (!empty(Config::get(self::AUTH_FREEIPA_REALM))) {
      $this->realm = Config::get(self::AUTH_FREEIPA_REALM);
    } elseif (!$this->discover_kerberos_realm()) {
      $this->realm = strtoupper($this->domain);
      $this->log("Unable to discover local realm via DNS. Using {$this->realm}, hope that's ok", E_USER_WARNING);
    }

    // get ldap servers
    if (!empty(Config::get(self::AUTH_FREEIPA_LDAP_URI))) {
      $this->ldap_uri = Config::get(self::AUTH_FREEIPA_LDAP_URI);
    } elseif (!$this->discover_ldap_servers()) {
      $this->log("Failed to discover local LDAP servers via DNS. Try setting " . self::AUTH_FREEIPA_LDAP_URI, E_USER_ERROR);
      return false;
    }

    // connect to ldap server
    if (!($this->ldapconn = ldap_connect($this->ldap_uri))) {
      return false;
    }

    // set protocol version 3
    if (!ldap_set_option($this->ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3)) {
      return false;
    }

    // start TLS session
    if(!ldap_start_tls($this->ldapconn)) {
      return false;
    }

    // bind to ldap server using kerberos credentials
    if (!ldap_sasl_bind($this->ldapconn, null, null, 'GSSAPI')) {
      return false;
    }

    // get base dn
    if (!empty(Config::get(self::AUTH_FREEIPA_BASEDN))) {
      $this->basedn = Config::get(self::AUTH_FREEIPA_BASEDN);
    } elseif (!$this->discover_basedn()) {
      $this->guess_basedn_from_realm();
      $this->log("Unable to determine basedn via LDAP query. Using {$this->basedn}, hope that's ok", E_USER_WARNING);
    }

    return $this->ready = true;
  }

  function authenticate($username = null, $password = null, $service = '') {
    if (!$this->_init()) {
      return false;
    }

    /* First, attempt SSO/Kerberos-style authentication by checking the REMOTE_USER
     * header set by the webserver. If this succeeds, then we'll SASL bind to the
     * LDAP server to perform the user attribute and group queries.
     *
     * If REMOTE_USER is not set, attempt a simple bind using the provided username
     * and password.
     */
    if ($remote_user = $this->authenticate_via_remote()) {
      $username = $remote_user;
      $auth_via = 'sso';
    } elseif ($username && $this->authenticate_via_ldap($username, $password)) {
      $auth_via = 'ldap';
    } else {
      return false;
    }

    /* At this point, the user has been authenticated, either by the REMOTE_USER
     * variable or a successful LDAP bind.
     *
     * Now we will verify group membership (if requested by configuration) and
     * retrieve user attributes like mail and displayName.
     */
    $allow_groups = array_map([$this, 'groupdn'], preg_split('/[,:\s]+/', Config::get(self::AUTH_FREEIPA_ALLOW_GROUPS), -1, PREG_SPLIT_NO_EMPTY));
    $admin_groups = array_map([$this, 'groupdn'], preg_split('/[,:\s]+/', Config::get(self::AUTH_FREEIPA_ADMIN_GROUPS), -1, PREG_SPLIT_NO_EMPTY));
    $filter = $allow_groups ? '(|(' . implode(')(', preg_filter('/^/', 'memberOf=', array_merge($allow_groups, $admin_groups))) . '))' : null;

    if ($user = $this->ldap_get_user($username, $filter)) {
      if ($userid = $this->auto_create_user($username)) {
        if (Config::get(Config::AUTH_AUTO_CREATE)) {

          if ($fullname = $user['displayName'][0]) {
            $sth = $this->pdo->prepare('UPDATE ttrss_users SET full_name = ? WHERE id = ?');
            $sth->execute([$fullname, $userid]);
          }

          if ($email = $user['mail'][0]) {
            $sth = $this->pdo->prepare('UPDATE ttrss_users SET email = ? WHERE id = ?');
            $sth->execute([$email, $userid]);
          }

          if ($admin_groups) {
            $admin_filter = '(|(' . implode(')(', preg_filter('/^/', 'memberOf=', $admin_groups)) . '))';
            $access_level = $this->ldap_get_user($username, $admin_filter) ? 10 : 0;

            $sth = $this->pdo->prepare('UPDATE ttrss_users SET access_level = ? WHERE id = ?');
            $sth->execute([$access_level, $userid]);
          }
        }

        $this->log("freeipa user $username authenticated via $auth_via");
        return $userid;
      }
    }
    return false;
  }

  function api_version() {
    return 2;
  }
}
