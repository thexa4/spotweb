<?php

/*
 * Allows users to log in using ldap credentials
 */
class SpotLdap {
	private $_conn = null;

    function __construct($settings, $db) {
        $this->_settings = $settings;
        $this->_conf = $settings->get('ldap');
        $this->_db = $db;
	} # __ctor

	/*
	 * Open connection to Ldap and authenticate
	 */
	function connect() {
        SpotTiming::start(__FUNCTION__);

        $this->_conn = ldap_connect($this->_conf['host']);
        ldap_set_option($this->_conn, LDAP_OPT_PROTOCOL_VERSION, $this->_conf['version']);
        $this->bind();

		SpotTiming::stop(__FUNCTION__);
    } # connect

    /*
     *  Resets the login credentials
     */
    function bind()
    {
        if(!empty($this->_conf['user']))
        {
            if(!ldap_bind($this->_conn, $this->_conf['user'], $this->_conf['pass']))
                throw new Exception('Could not bind to LDAP');
        }
        else
        {
            if(!ldap_bind($this->_conn))
                throw new Exception('Could not bind to LDAP');
        }
    }

	/*
	 * Returns the Ldap handle
	 */
	function getLdapHandle() {
		return $this->_conn;
	} # getDbHandle

	/*
     * Tries to log in with username and plain text password
     * Creates a new user in the database if ldap user doesn't exist yet
	 *
	 * Returns a userid if the user can be found or false on failure
	 */
    function authUser($username, $password) {
        // Protection for windows AD
        if($password == '')
            return false;

        // Remove parentheses to avoid injections
        $username = str_replace(['(',')','*'], '', $username);
        $query = '(&' . $this->_conf['user_filter'] . '(' . $this->_conf['attributes']['uid'] . '=' . $username . '))';

        $search = ldap_search($this->_conn, $this->_conf['base'], $query);
        if(ldap_count_entries($this->_conn, $search) == 0)
            return false;

        $user = ldap_get_entries($this->_conn, $search)[0];
        $dn = $user['dn'];

        $result = ldap_bind($this->_conn, $dn, $password);
        // Reset previous bind
        $this->bind();

        if(!$result)
            return false;

        $res = $this->_db->findUserIdForName($username);
        if(empty($res))
        {
            // Create new ldap user
            $newuser = array();
            $newuser['username'] = $username;
            
            $newuser['firstname'] = $user[$this->_conf['attributes']['firstname']][0];
            $newuser['lastname'] = $user[$this->_conf['attributes']['lastname']][0];
            $newuser['mail'] = $user[$this->_conf['attributes']['mail']][0];

            $newuser['newpassword1'] = '';

            $userSystem = new SpotUserSystem($this->_db, $this->_settings);
            $userSystem->addUser($newuser);

            $dbuser = $this->_db->getUser($this->_db->findUserIdForName($username));

            // Make sure user can't log in by using mysql
            $dbuser['passhash'] = '';
            $this->_db->setUserPassword($dbuser);
        }

        $user = $this->_db->getUser($this->_db->findUserIdForName($username));

        // Get group membership from ldap and (re)apply
        $groups = $this->_db->getGroupList(null);
        $newgroups = array();
        $prio = 1;
        foreach($groups as $group)
        {
            if(!isset($this->_conf['groups'][$group['name']]))
                continue;
            $dn = $this->_conf['groups'][$group['name']];

            if($dn != '*')
            {
                $ldapgroup = ldap_search($this->_conn, $dn, '(objectClass=*)');
                if(ldap_count_entries($this->_conn, $ldapgroup) == 0)
                    throw new Exception('Invalid dn for ' . $group['name']);

                $ldapgroup = ldap_get_entries($this->_conn, $ldapgroup)[0];
                $members = $ldapgroup[$this->_conf['attributes']['memberof']];

                if(!in_array($username, $members))
                    continue;
            }

            $newgroups[] = array('groupid' => $group['id'], 'prio' => $prio++);
        }
        $this->_db->setUserGroupList($user['userid'], $newgroups);

        return $user['userid'];
	} # authUser

} # class ldap
