<?php

namespace Bbt\Sso;

class Encrypter {
    private const CIPHER = 'aes-256-cbc';
    private $secret;

    function __construct(string $secret){
        $this->secret = $secret;
    }

    public function encrypt($data){
        $cipher_length = openssl_cipher_iv_length(self::CIPHER);
        $iv = openssl_random_pseudo_bytes($cipher_length);

        $encrypted = openssl_encrypt($data, self::CIPHER, $this->secret, 0, $iv);

        $result = base64_encode($iv).'.'.$encrypted;

        return $result;
    }

    public function decrypt($encrypted){
        $parts = explode('.', $encrypted);

        $decrypted = openssl_decrypt($parts[1], self::CIPHER, $this->secret, 0, base64_decode($parts[0]));
        
        return $decrypted;
    }
}