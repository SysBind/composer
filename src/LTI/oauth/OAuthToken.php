<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI\oauth;

/**
 * 
 * Represent an OAuth Token
 * 
 * @author SysBind
 *
 */
class OAuthToken
{
    /**
     * 
     * @var string $key consumer key
     */
    public $key;
    
    /**
     * 
     * @var string $secret consumer secret
     */
    public $secret;
    
    /**
     * Constuctor
     * 
     * @param string $key
     * @param string $secret
     */
    function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }
    
    /**
     * helper function for __toString
     * 
     * @return string
     */
    private function to_string()
    {
        return "oauth_token=" .  OAuthUtil::urlencode_rfc3986($this->key) . 
        "&oauth_token_secret=" . OAuthUtil::urlencode_rfc3986($this->secret);
    }
    
    /**
     * return the objact data as string
     * 
     * @return string
     */
    public function __toString()
    {
        return $this->to_string();
    }
}

?>