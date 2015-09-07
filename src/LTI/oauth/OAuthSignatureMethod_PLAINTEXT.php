<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI\oauth;

/**
 * Class for signature used plain text
 * 
 * @author SysBind
 *
 */
class OAuthSignatureMethod_PLAINTEXT extends OAuthSignatureMethod
{
    /**
     * Return signature type
     * 
     * @return string the name of the OAuth Signature Method
     */
    public function get_name()
    {
        return "PLAINTEXT";
    }
    
    /**
     * Build a signature encode in plain text
     * 
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * 
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthSignatureMethod::build_signature()
     */
    public function build_signature($request, $consumer, $token)
    {
        $sig = array(
            OAuthUtil::urlencode_rfc3986($consumer->secret)
        );
        
        if ($token) {
            array_push($sig, OAuthUtil::urlencode_rfc3986($token->secret));
        } else {
            array_push($sig, '');
        }
        
        $raw = implode("&", $sig);
        // for debug purposes
        $request->base_string = $raw;
        
        return OAuthUtil::urlencode_rfc3986($raw);
    }
}

?>