<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI;

use LTI\oauth\OAuthDataStore;
use LTI\oauth\OAuthConsumer;
use LTI\oauth\OAuthToken;

/**
 * Data store object 
 * 
 * @author SysBind
 *
 */
class TrivialOAuthDataStore extends OAuthDataStore
{
    
    /**
     * 
     * @var array array of all consumers
     */
    private $consumers = array();

    /**
     * add a consumer
     * 
     * @param string $consumer_key
     * @param string $consumer_secret
     */
    public function add_consumer($consumer_key, $consumer_secret)
    {
        $this->consumers[$consumer_key] = $consumer_secret;
    }

    /**
     * Search for consumer based on his key
     * 
     * @param string $consumer_key
     *  
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
     * Search a tokn for a consumer 
     * 
     * @param OAuthConsumer $consumer
     * @param string $token_type
     * @param OAuthToken $token
     * 
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
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * @param string $nonce
     * @param int|string $timestamp
     * 
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::lookup_nonce()
     */
    public function lookup_nonce($consumer, $token, $nonce, $timestamp)
    {
        // Should add some clever logic to keep nonces from
        // being reused - for no we are really trusting
        // that the timestamp will save us
        return !apc_add($consumer . $timestamp , $nonce,1800);
    }

    /**
     * Generate new request token
     * 
     * @param OAuthConsumer $consumer
     * 
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::new_request_token()
     */
    public function new_request_token($consumer)
    {
        return NULL;
    }

    /**
     * generate new access token
     * 
     * @param OAuthToken $token
     * @param OAuthConsumer $consumer
     * 
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthDataStore::new_access_token()
     */
    public function new_access_token($token, $consumer)
    {
        return NULL;
    }
}

?>