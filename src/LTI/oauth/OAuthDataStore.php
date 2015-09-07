<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI\oauth;


/**
 * Class used for work with OAuth data
 * 
 * @author SysBind
 *
 */
abstract class OAuthDataStore
{
    /**
     * Search for consumer by his key
     * 
     * @param string $consumer_key
     */
    abstract function lookup_consumer($consumer_key);

    /**
     * Search for token for a consumer
     * 
     * @param OAuthConsumer $consumer
     * @param string $token_type
     * @param OAuthToken $token
     */
    abstract function lookup_token($consumer, $token_type, $token);

    /**
     * Search for nonce string in specific time for a coustumer
     * 
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * @param string $nonce
     * @param string|int $timestamp
     */
    abstract function lookup_nonce($consumer, $token, $nonce, $timestamp);
    
    /**
     * Create new request token for a consumer
     *      
     * @param OAuthConsumer $consumer
     */
    abstract  function new_request_token($consumer);

    /**
     * return a new access token attached to this consumer for the user 
     * associated with this token if the request token is authorized should 
     * also invalidate the request token
     * 
     * @param OAuthToken $token
     * @param OAuthConsumer $consumer
     */
    abstract function new_access_token($token, $consumer);
}

?>