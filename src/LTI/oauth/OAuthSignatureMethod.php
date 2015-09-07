<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI\oauth;

/**
 * abstract class for OAuth signature 
 * 
 * @author SysBind
 *
 */
abstract class OAuthSignatureMethod
{
    /**
     * test OAuth signature
     * 
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * @param string $signature
     * 
     * @return boolean
     */
    public function check_signature(&$request, $consumer, $token, $signature) {
        $built = $this->build_signature($request, $consumer, $token);
        return $built == $signature;
    }
    
    /**
     * Build signature
     * 
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     */
    abstract public function build_signature($request, $consumer, $token);
}

?>