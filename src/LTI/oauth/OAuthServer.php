<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI\oauth;

/**
 * Class to manage the OAuth server
 * 
 * @author SysBind
 *
 */
class OAuthServer
{
    /**
     * 
     * @var int $timestamp_threshold in seconds, five minutes
     */
    protected $timestamp_threshold = 300;

    /**
     * 
     * @var float $version OAuth server version
     */
    protected $version = 1.0;
 
    /**
     * 
     * @var array $signature_methods array contain the encode methods of the signature
     */
    protected $signature_methods = array();

    /**
     * 
     * @var OAuthDataStore $data_store the data store object
     */
    protected $data_store;

    
    /**
     * Constructor
     * 
     * @param OAuthDataStore $data_store the data store object
     */
    function __construct($data_store)
    {
        $this->data_store = $data_store;
    }

    /**
     * add signature encode to the OAuth Server check
     * 
     * @param OAuthSignatureMethod $signature_method
     */
    public function add_signature_method($signature_method)
    {
        $this->signature_methods[$signature_method->get_name()] = $signature_method;
    }
    

    /**
     * process a request_token request
     * returns the request token on success
     * 
     * @param OAuthRequest $request
     * @return unknown
     */
    public function fetch_request_token(&$request)
    {
        $this->get_version($request);
        
        $consumer = $this->get_consumer($request);
        
        // no token required for the initial token request
        $token = NULL;
        
        $this->check_signature($request, $consumer, $token);
        
        $new_token = $this->data_store->new_request_token($consumer);
        
        return $new_token;
    }

    /**
     * process an access_token request
     * returns the access token on success
     * 
     * @param OAuthRequest $request
     * @return unknown
     */
    public function fetch_access_token(&$request)
    {
        $this->get_version($request);
        
        $consumer = $this->get_consumer($request);
        
        // requires authorized request token
        $token = $this->get_token($request, $consumer, "request");
        
        $this->check_signature($request, $consumer, $token);
        
        $new_token = $this->data_store->new_access_token($token, $consumer);
        
        return $new_token;
    }

    /**
     * verify an api call, checks all the parameters
     * 
     * @param unknown $request
     * @return multitype:\LTI\oauth\unknown Ambigous <boolean, unknown>
     */
    public function verify_request(&$request)
    {
        global $OAuth_last_computed_signature;
        $OAuth_last_computed_signature = false;
        $this->get_version($request);
        $consumer = $this->get_consumer($request);
        $token = $this->get_token($request, $consumer, "access");
        $this->check_signature($request, $consumer, $token);
        return array(
            $consumer,
            $token
        );
    }
    
    /**
     * Return the OAuth sever version
     * 
     * @param OAuthRequest $request
     * @throws OAuthException
     * @return number
     */
    private function get_version(&$request)
    {
        $version = $request->get_parameter("oauth_version");
        if (! $version) {
            $version = 1.0;
        }
        if ($version && $version != $this->version) {
            throw new OAuthException("OAuth version '$version' not supported");
        }
        return $version;
    }


    /**
     * figure out the signature with some defaults
     * 
     * @param OAuthRequest $request
     * @throws OAuthException
     * @return array
     */
    private function get_signature_method(&$request)
    {
        $signature_method = @$request->get_parameter("oauth_signature_method");
        if (! $signature_method) {
            $signature_method = "PLAINTEXT";
        }
        if (! in_array($signature_method, array_keys($this->signature_methods))) {
            throw new OAuthException("Signature method '$signature_method' not supported " . "try one of the following: " . implode(", ", array_keys($this->signature_methods)));
        }
        return $this->signature_methods[$signature_method];
    }

    /**
     * try to find the consumer for the provided request's consumer key
     * 
     * @param OAuthRequest $request
     * @throws OAuthException
     * @return unknown
     */
    private function get_consumer(&$request)
    {
        $consumer_key = @$request->get_parameter("oauth_consumer_key");
        if (! $consumer_key) {
            throw new OAuthException("Invalid consumer key");
        }
        
        $consumer = $this->data_store->lookup_consumer($consumer_key);
        if (! $consumer) {
            throw new OAuthException("Invalid consumer");
        }
        
        return $consumer;
    }


    /**
     * try to find the token for the provided request's token key
     * 
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param string $token_type
     * @throws OAuthException
     * @return boolean|unknown
     */
    private function get_token(&$request, $consumer, $token_type = "access")
    {
        $token_field = @$request->get_parameter('oauth_token');
        if (! $token_field)
            return false;
        $token = $this->data_store->lookup_token($consumer, $token_type, $token_field);
        if (! $token) {
            throw new OAuthException("Invalid $token_type token: $token_field");
        }
        return $token;
    }

    /**
     * all-in-one function to check the signature on a request
     * should guess the signature method appropriately
     * 
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * @throws OAuthException
     */
    private function check_signature(&$request, $consumer, $token)
    {
        // this should probably be in a different method
        global $OAuth_last_computed_signature;
        $OAuth_last_computed_signature = false;
        
        $timestamp = @$request->get_parameter('oauth_timestamp');
        $nonce = @$request->get_parameter('oauth_nonce');
        
        $this->check_timestamp($timestamp);
        $this->check_nonce($consumer, $token, $nonce, $timestamp);
        
        $signature_method = $this->get_signature_method($request);
        
        $signature = $request->get_parameter('oauth_signature');
        $valid_sig = $signature_method->check_signature($request, $consumer, $token, $signature);
        
        if (! $valid_sig) {
            $ex_text = "Invalid signature";
            if ($OAuth_last_computed_signature) {
                $ex_text = $ex_text . " ours= $OAuth_last_computed_signature yours=$signature";
            }
            throw new OAuthException($ex_text);
        }
    }

    /**
     * check that the timestamp is new enough
     * 
     * @param string|int $timestamp
     * @throws OAuthException
     */
    private function check_timestamp($timestamp)
    {
        // verify that timestamp is recentish
        $now = time();
        if ($now - $timestamp > $this->timestamp_threshold) {
            throw new OAuthException("Expired timestamp, yours $timestamp, ours $now");
        }
    }


    /**
     * check that the nonce is not repeated
     * 
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * @param string $nonce
     * @param string|int $timestamp
     * @throws OAuthException
     */
    private function check_nonce($consumer, $token, $nonce, $timestamp)
    {
        // verify that the nonce is uniqueish
        $found = $this->data_store->lookup_nonce($consumer, $token, $nonce, $timestamp);
        if ($found) {
            throw new OAuthException("Nonce already used: $nonce");
        }
    }
}

?>