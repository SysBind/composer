<?php
namespace LTI\oauth;

class OAuthToken
{
    public $key;
    public $secret;
    
    function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }
    
    private function to_string()
    {
        return "oauth_token=" .  OAuthUtil::urlencode_rfc3986($this->key) . 
        "&oauth_token_secret=" . OAuthUtil::urlencode_rfc3986($this->secret);
    }
    
    public function __toString()
    {
        return $this->to_string();
    }
}

?>