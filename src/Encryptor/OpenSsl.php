<?php

namespace Phlib\Encrypt\Encryptor;

if (!function_exists('hash_equals')) {
    function hash_equals($a, $b) {
        $key = openssl_random_pseudo_bytes(16);
        return hash_hmac('sha256', $a, $key) === hash_hmac('sha256', $b, $key);
    }
}

use Phlib\Encrypt\EncryptorInterface;
use Phlib\Encrypt\InvalidArgumentException;
use Phlib\Encrypt\RuntimeException;

class OpenSsl implements EncryptorInterface
{
    /**
     * @var string
     */
    protected $password;

    /**
     * @var string
     */
    protected $cipherMethod = 'aes-256-cbc';

    /**
     * @var int
     */
    protected $pbkdf2Iterations = 50000;

    /**
     * @var int
     */
    protected $saltLength = 8;
    protected $ivLength   = null; // dependant on cipher method
    protected $macLength  = 32;   // strlen(hash_hmac('sha256', '', '', true))

    /**
     * OpenSsl constructor
     *
     * @param string $password
     */
    public function __construct($password)
    {
        $this->password = $password;
        $this->ivLength = openssl_cipher_iv_length($this->cipherMethod);
    }

    /**
     * @param string $data
     * @return string
     */
    public function encrypt($data)
    {
        $salt = openssl_random_pseudo_bytes($this->saltLength);
        $iv   = openssl_random_pseudo_bytes($this->ivLength);
        $key  = hash_pbkdf2('sha256', $this->password, $salt, $this->pbkdf2Iterations, 0, true);

        $encryptedData = openssl_encrypt($data, $this->cipherMethod, $key, OPENSSL_RAW_DATA, $iv);
        $mac = hash_hmac('sha256', $encryptedData . $iv, $key, true);

        return $salt . $iv . $mac . $encryptedData;
    }

    /**
     * @param string $data
     * @return string
     */
    public function decrypt($data)
    {
        if (strlen($data) < $this->saltLength + $this->ivLength + $this->macLength) {
            throw new InvalidArgumentException('Data is not valid for decryption');
        }
        $salt          = substr($data, 0, $this->saltLength);
        $iv            = substr($data, $this->saltLength, $this->ivLength);
        $mac           = substr($data, $this->saltLength + $this->ivLength, $this->macLength);
        $encryptedData = substr($data, $this->saltLength + $this->ivLength + $this->macLength);

        $key = hash_pbkdf2('sha256', $this->password, $salt, $this->pbkdf2Iterations, 0, true);
        $calculatedMac = hash_hmac('sha256', $encryptedData . $iv, $key, true);

        if (!hash_equals($calculatedMac, $mac)) {
            throw new RuntimeException('HMAC failed to match');
        }

        $decryptedData = openssl_decrypt($encryptedData, $this->cipherMethod, $key, OPENSSL_RAW_DATA, $iv);

        if ($decryptedData === false) {
            throw new RuntimeException('Failed to decrypt data');
        }

        return $decryptedData;
    }

}
