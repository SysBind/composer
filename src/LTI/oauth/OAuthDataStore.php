<?php
namespace LTI\oauth;

abstract class OAuthDataStore
{

    abstract function lookup_consumer($consumer_key);

    abstract function lookup_token($consumer, $token_type, $token);

    abstract function lookup_nonce($consumer, $token, $nonce, $timestamp);
    
    abstract  function new_request_token($consumer);

    /**
     * return a new access token attached to this consumer for the user 
     * associated with this token if the request token is authorized should 
     * also invalidate the request token
     * 
     * @param unknown $token
     * @param unknown $consumer
     */
    abstract function new_access_token($token, $consumer);
}

?>