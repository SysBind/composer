<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI\oauth;

/**
 * Class represent LTI consumer
 * 
 * @author SysBind
 *
 */
class OAuthConsumer
{
    /**
     * 
     * @var string consumer key
     */
    public $key;
    
    /**
     * 
     * @var string consumer secret
     */
    public $secret;
    
    /**
     * Constuctor
     * 
     * @param string $key
     * @param string $secret
     * @param string $callback_url
     */
    function __construct($key, $secret, $callback_url=NULL) 
    {
        $this->key = $key;
        $this->secret = $secret;
        $this->callback_url = $callback_url;
    }
    
    /**
     * Return consumer data in string
     * 
     * @return string
     */
    public function __toString()
    {
        return "OAuthConsumer[key=$this->key,secret=$this->secret]";
        
    }
}

?>