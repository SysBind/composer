<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
 
namespace LTI;

use LTI\oauth\OAuthServer;
use LTI\oauth\OAuthSignatureMethod_HMAC_SHA1;
use LTI\oauth\OAuthRequest;

/**
 * LTI provider version 1.1.1
 * 
 * @author Sysbind
 *
 */
class BLTI
{

    /**
     * 
     * @var boolean flag about reauest validation
     */
    public $valid = false;

    /**
     * 
     * @var boolean is the request completed
     */
    public $complete = false;

    /**
     * 
     * @var string|false Message that can be return or display
     */
    public $message = false;

    /**
     * 
     * @var string|false string represnt the lti request
     */
    public $basestring = false;

    /**
     * 
     * @var array|false array contain all the data collect from the lti consumer request
     */
    public $info = false;

    /**
     * 
     * @var array|false row data about the consumer
     */
    public $row = false;

    /**
     * 
     * @var int|false the request context id
     */
    public $context_id = false;
    
    /**
     * Constructor
     * 
     * @param string $parm
     * @param string $usesession
     * @param string $doredirect
     * @param \PDO $pdo
     */
    function __construct($parm = false, $usesession = true, $doredirect = true, \PDO $pdo)
    {
        // If this request is not an LTI Launch, either
        // give up or try to retrieve the context from session
        if (! $this->is_basic_lti_request()) {
            if ($usesession === false)
                return;
            if (strlen(session_id()) > 0) {
                $row = $_SESSION['_basiclti_lti_row'];
                if (isset($row))
                    $this->row = $row;
                $context_id = $_SESSION['_basiclti_lti_context_id'];
                if (isset($context_id))
                    $this->context_id = $context_id;
                $info = $_SESSION['_basic_lti_context'];
                if (isset($info)) {
                    $this->info = $info;
                    $this->valid = true;
                    return;
                }
                $this->message = "Could not find context in session";
                return;
            }
            $this->message = "Session not available";
            return;
        }
        
        // Insure we have a valid launch
        if (empty($_REQUEST["oauth_consumer_key"])) {
            $this->message = "Missing oauth_consumer_key in request";
            return;
        }
        $oauth_consumer_key = ctype_alnum($_REQUEST["oauth_consumer_key"])? $_REQUEST["oauth_consumer_key"] : null;
        
        // Find the secret - either form the parameter as a string or
        // look it up in a database from parameters we are given
        $secret = false;
        $row = false;
        if (is_string($parm)) {
            $secret = $parm;
        } else 
            if (! is_array($parm)) {
                $this->message = "Constructor requires a secret or database information.";
                return;
            } else {
                $sql = 'SELECT * FROM ' . $parm['table'] . ' WHERE ' . (isset($parm['key_column']) ? $parm['key_column'] : 'oauth_consumer_key') . '='  . $pdo->quote($oauth_consumer_key) ;
                $result = $pdo->query($sql);
                $num_rows = $result->rowCount();
                if ($num_rows != 1) {
                    $this->message = "Your consumer is not authorized oauth_consumer_key=" . $oauth_consumer_key;
                    return;
                } else {
                    while ($row = $result->fetch(\PDO::FETCH_ASSOC)) {
                        $secret = $row[isset($parm['secret_column']) ? $parm['secret_column'] : 'secret'];
                        $context_id = $row[isset($parm['context_column']) ? $parm['context_column'] : 'context_id'];
                        if ($context_id) {
                            $this->context_id = $context_id;
                        }
                        $this->row = $row;
                        break;
                    }
                    if (! is_string($secret)) {
                        $this->message = "Could not retrieve secret oauth_consumer_key=" . $oauth_consumer_key;
                        return;
                    }
                }
            }
        
        // Verify the message signature
        $store = new TrivialOAuthDataStore();
        $store->add_consumer($oauth_consumer_key, $secret);
        
        $server = new OAuthServer($store);
        
        $method = new OAuthSignatureMethod_HMAC_SHA1();
        $server->add_signature_method($method);
        $request = OAuthRequest::from_request();
        
        $this->basestring = $request->get_signature_base_string();
        
        try {
            $server->verify_request($request);
            $this->valid = true;
        } catch (Exception $e) {
            $this->message = $e->getMessage();
            return;
        }
        
        // Store the launch information in the session for later
        $newinfo = array();
        foreach ($_POST as $key => $value) {
            if ($key == "basiclti_submit")
                continue;
            if (strpos($key, "oauth_") === false) {
                $newinfo[$key] = $value;
                continue;
            }
            if ($key == "oauth_consumer_key") {
                $newinfo[$key] = $value;
                continue;
            }
        }
        
        $this->info = $newinfo;
        if ($usesession == true and strlen(session_id()) > 0) {
            $_SESSION['_basic_lti_context'] = $this->info;
            unset($_SESSION['_basiclti_lti_row']);
            unset($_SESSION['_basiclti_lti_context_id']);
            if ($this->row)
                $_SESSION['_basiclti_lti_row'] = $this->row;
            if ($this->context_id)
                $_SESSION['_basiclti_lti_context_id'] = $this->context_id;
        }
        
        if ($this->valid && $doredirect) {
            $this->redirect();
            $this->complete = true;
        }
    }
    
    /**
     * Check if the request is lti request
     * 
     * Retrun true if the request is basic lti request
     * @return boolean
     */
    protected function is_basic_lti_request() {
        $good_message_type = (isset($_REQUEST["lti_message_type"]) && ($_REQUEST["lti_message_type"] == "basic-lti-launch-request"));
        $good_lti_version = (isset($_REQUEST["lti_message_type"]) && ($_REQUEST["lti_version"] == "LTI-1p0"));
        $resource_link_id = isset($_REQUEST["resource_link_id"]) ? $_REQUEST["resource_link_id"]: null;
        if ($good_message_type and $good_lti_version and isset($resource_link_id) ) return(true);
        return false;
    }
    
    /**
     * Return session name anfd number
     * 
     * check if there is session data in cookies
     * 
     * @param string $location
     * @return string
     */
    public function addSession($location) {
        if ( ini_get('session.use_cookies') == 0 ) {
            if ( strpos($location,'?') > 0 ) {
                $location = $location . '&';
            } else {
                $location = $location . '?';
            }
            $location = $location . session_name() . '=' . session_id();
        }
        return $location;
    }
    
    /**
     * Check if the user has role instructor or admin in the LTI consumer
     * 
     * @return boolean
     */
    public function isInstructor() {
        $roles = isset($this->info['roles']) ? $this->info['roles'] : null;
        $roles = strtolower($roles);
        if ( ! ( strpos($roles,"instructor") === false ) ) return true;
        if ( ! ( strpos($roles,"administrator") === false ) ) return true;
        return false;
    }
    
    /**
     * Return the consumer user Email
     * 
     * @return string|boolean
     */
    public function getUserEmail() {
        $email = $this->info['lis_person_contact_email_primary'];
        if ( strlen($email) > 0 ) return $email;
        # Sakai Hack
        $email = $this->info['lis_person_contact_emailprimary'];
        if ( strlen($email) > 0 ) return $email;
        return false;
    }
    
    /**
     * Return user shortname
     * 
     * @return string|false
     */
    public function getUserShortName() {
        $email = $this->getUserEmail();
        $givenname = $this->info['lis_person_name_given'];
        $familyname = $this->info['lis_person_name_family'];
        $fullname = $this->info['lis_person_name_full'];
        if ( strlen($email) > 0 ) return $email;
        if ( strlen($givenname) > 0 ) return $givenname;
        if ( strlen($familyname) > 0 ) return $familyname;
        return $this->getUserName();
    }
    
    /**
     * Return the user name
     * 
     * @return string|false
     */
    public function getUserName() {
        $givenname = $this->info['lis_person_name_given'];
        $familyname = $this->info['lis_person_name_family'];
        $fullname = $this->info['lis_person_name_full'];
        if ( strlen($fullname) > 0 ) return $fullname;
        if ( strlen($familyname) > 0 and strlen($givenname) > 0 ) return $givenname.$familyname;
        if ( strlen($givenname) > 0 ) return $givenname;
        if ( strlen($familyname) > 0 ) return $familyname;
        return $this->getUserEmail();
    }
    
    /**
     * Get the consumer key
     * 
     * @return string|false
     */
    public function getUserKey() {
        $oauth = $this->info['oauth_consumer_key'];
        $id = $this->info['user_id'];
        if ( strlen($id) > 0 and strlen($oauth) > 0 ) return $oauth . ':' . $id;
        return false;
    }
    
    /**
     * Return a path to the user image
     * 
     * @return string
     */
    public function getUserImage() {
        $image = isset($this->info['user_image']) ? $this->info['user_image'] : null;
        if ( strlen($image) > 0 ) return $image;
        $email = $this->getUserEmail();
        if ( $email === false ) return false;
        $size = 40;
        $grav_url = isset($_SERVER['HTTPS']) ? 'https://' : 'http://';
        $grav_url = $grav_url . "www.gravatar.com/avatar.php?gravatar_id=".md5( strtolower($email) )."&size=".$size;
        return $grav_url;
    }
    
    /**
     * Return consumer key
     * 
     * @return string|boolean
     */
    public function getResourceKey() {
        $oauth = $this->info['oauth_consumer_key'];
        $id = $this->info['resource_link_id'];
        if ( strlen($id) > 0 and strlen($oauth) > 0 ) return $oauth . ':' . $id;
        return false;
    }
    
    /**
     * Return resource link title if exist
     * 
     * @return string|boolean
     */
    public function getResourceTitle() {
        $title = $this->info['resource_link_title'];
        if ( strlen($title) > 0 ) return $title;
        return false;
    }
    
    /**
     * Return the consumer key
     * 
     * @return string|null
     */
    public function getConsumerKey() {
        $oauth = $this->info['oauth_consumer_key'];
        return $oauth;
    }
    
    /**
     * Return the course key
     * 
     * @return Ambigous <int, false>|string|boolean
     */
    public function getCourseKey() {
        if ( $this->context_id ) return $this->context_id;
        $oauth = $this->info['oauth_consumer_key'];
        $id = $this->info['context_id'];
        if ( strlen($id) > 0 and strlen($oauth) > 0 ) return $oauth . ':' . $id;
        return false;
    }
    
    /**
     * Return the course name
     * 
     * @return Ambigous <array, false>|boolean
     */
    public function getCourseName() {
        $label = $this->info['context_label'];
        $title = $this->info['context_title'];
        $id = $this->info['context_id'];
        if ( strlen($label) > 0 ) return $label;
        if ( strlen($title) > 0 ) return $title;
        if ( strlen($id) > 0 ) return $id;
        return false;
    }
    
    /**
     *  redirect the user
     */
    public function redirect() {
        $host = $_SERVER['HTTP_HOST'];
        $uri = $_SERVER['PHP_SELF'];
        $location = isset($_SERVER['HTTPS']) ? 'https://' : 'http://';
        $location = $location . $host . $uri;
        $location = $this->addSession($location);
        header("Location: $location");
    }
    
    /**
     * Return string that show all the data crom the lti request
     * 
     * @return string
     */
    public function dump() {
        if ( ! $this->valid or $this->info == false ) return "Context not valid\n";
        $ret = "";
        if ( $this->isInstructor() ) {
            $ret .= "isInstructor() = true\n";
        } else {
            $ret .= "isInstructor() = false\n";
        }
        $ret .= "getUserKey() = ".$this->getUserKey()."\n";
        $ret .= "getUserEmail() = ".$this->getUserEmail()."\n";
        $ret .= "getUserShortName() = ".$this->getUserShortName()."\n";
        $ret .= "getUserName() = ".$this->getUserName()."\n";
        $ret .= "getUserImage() = ".$this->getUserImage()."\n";
        $ret .= "getResourceKey() = ".$this->getResourceKey()."\n";
        $ret .= "getResourceTitle() = ".$this->getResourceTitle()."\n";
        $ret .= "getCourseName() = ".$this->getCourseName()."\n";
        $ret .= "getCourseKey() = ".$this->getCourseKey()."\n";
        $ret .= "getConsumerKey() = ".$this->getConsumerKey()."\n";
        return $ret;
    }
}

?>