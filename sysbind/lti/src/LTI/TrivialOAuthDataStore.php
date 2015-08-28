<?php
namespace LTI;

use LTI\oauth\OAuthDataStore;
use LTI\oauth\OAuthConsumer;

class TrivialOAuthDataStore extends OAuthDataStore
{

    private $consumers = array();

    /**
     * 
     * @param unknown $consumer_key
     * @param unknown $consumer_secret
     */
    function add_consumer($consumer_key, $consumer_secret)
    {
        $this->consumers[$consumer_key] = $consumer_secret;
    }

    /**
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::lookup_consumer()
     */
    public function lookup_consumer($consumer_key)
    {
        if (strpos($consumer_key, "http://") === 0) {
            $consumer = new OAuthConsumer($consumer_key, "secret", NULL);
            return $consumer;
        }
        if ($this->consumers[$consumer_key]) {
            $consumer = new OAuthConsumer($consumer_key, $this->consumers[$consumer_key], NULL);
            return $consumer;
        }
        return NULL;
    }

    /**
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::lookup_token()
     */
    public function lookup_token($consumer, $token_type, $token)
    {
        return new OAuthToken($consumer, "");
    }
    
     
     
    /**
     * Return NULL if the nonce has not been used
     * Return $nonce if the nonce was previously used
     * 
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::lookup_nonce()
     */
    public function lookup_nonce($consumer, $token, $nonce, $timestamp)
    {
        // Should add some clever logic to keep nonces from
        // being reused - for no we are really trusting
        // that the timestamp will save us
        return NULL;
    }

    /**
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::new_request_token()
     */
    public function new_request_token($consumer)
    {
        return NULL;
    }

    /**
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::new_access_token()
     */
    public function new_access_token($token, $consumer)
    {
        return NULL;
    }
}

?>