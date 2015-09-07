<?php
/**
 * SysBind LTI provider (http://sysbind.co.il/)
 *
 * @link      https://github.com/SysBind/composer for the canonical source repository
 */
namespace LTI\oauth;

/**
 * Class for signature used RSA SHA1
 * 
 * @author SysBind
 *
 */
class OAuthSignatureMethod_RSA_SHA1 extends OAuthSignatureMethod
{
    
    /**
     * Return the signature encode type
     *
     * @return string
     */
    public function get_name()
    {
        return "RSA-SHA1";
    }
    
    /**
     * get the public certification
     * 
     * @param OAuthRequest $request
     */
    protected function fetch_public_cert(&$request) {
        // not implemented yet, ideas are:
        // (1) do a lookup in a table of trusted certs keyed off of consumer
        // (2) fetch via http using a url provided by the requester
        // (3) some sort of specific discovery code based on request
        //
        // either way should return a string representation of the certificate
        throw Exception("fetch_public_cert not implemented");
    }

    /**
     * get the private certification
     * 
     * @param OAuthRequest $request
     */
    protected function fetch_private_cert(&$request) {
        // not implemented yet, ideas are:
        // (1) do a lookup in a table of trusted certs keyed off of consumer
        //
        // either way should return a string representation of the certificate
        throw Exception("fetch_private_cert not implemented");
    }
    
    /**
     * Build the signature encode for RSA SHA1
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
        $base_string = $request->get_signature_base_string();
        $request->base_string = $base_string;
        
        // Fetch the private key cert based on the request
        $cert = $this->fetch_private_cert($request);
        
        // Pull the private key ID from the certificate
        $privatekeyid = openssl_get_privatekey($cert);
        
        // Sign using the key
        $ok = openssl_sign($base_string, $signature, $privatekeyid);
        
        // Release the key resource
        openssl_free_key($privatekeyid);
        
        return base64_encode($signature);
    }
    
    /**
     * Test the signature for RSA SHA1 encode
     * 
     * @param OAuthRequest $request
     * @param OAuthConsumer $consumer
     * @param OAuthToken $token
     * @param string $signature
     * 
     * (non-PHPdoc)
     * @see \LTI\oauth\OAuthSignatureMethod::check_signature()
     */
    public function check_signature(&$request, $consumer, $token, $signature) {
        $decoded_sig = base64_decode($signature);
    
        $base_string = $request->get_signature_base_string();
    
        // Fetch the public key cert based on the request
        $cert = $this->fetch_public_cert($request);
    
        // Pull the public key ID from the certificate
        $publickeyid = openssl_get_publickey($cert);
    
        // Check the computed signature against the one passed in the query
        $ok = openssl_verify($base_string, $decoded_sig, $publickeyid);
    
        // Release the key resource
        openssl_free_key($publickeyid);
    
        return $ok == 1;
    }
}

?>