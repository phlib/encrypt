<?php

namespace Phlib\Encrypt\Encryptor;

if (!function_exists('hash_equals')) {
    /**
     * hash_equals
     *
     * This function was introduced in PHP 5.6, this is provided as a backfill for earlier PHP versions
     *
     * @param string $a
     * @param string $b
     * @return bool
     */
    function hash_equals($a, $b) {
        $key = openssl_random_pseudo_bytes(16);
        return hash_hmac('sha256', $a, $key) === hash_hmac('sha256', $b, $key);
    }
}

if (!function_exists('hash_pbkdf2')) {
    /**
     * Generate a PBKDF2 key derivation of a supplied password
     *
     * This is a polyfill to account for pre-PHP5.5 versions
     * Implementation taken from http://stackoverflow.com/a/5093422/1602850
     * Modified to implement the $raw_output behaviour
     *
     * @link http://php.net/manual/en/function.hash-pbkdf2.php
     * @param $algo
     * @param $password
     * @param $salt
     * @param $iterations
     * @param $length [optional]
     * @param $raw_output [optional]
     * @return mixed a string containing the derived key as lowercase hexits unless
     * <i>raw_output</i> is set to <b>TRUE</b> in which case the raw
     * binary representation of the derived key is returned.
     * @since 5.5.0
     */
    function hash_pbkdf2($algo, $password, $salt, $iterations, $length, $raw_output) {
        $size   = strlen(hash($algo, '', true));
        $len    = ceil($length / $size);
        $result = '';
        for ($i = 1; $i <= $len; $i++) {
            $tmp = hash_hmac($algo, $salt . pack('N', $i), $password, true);
            $res = $tmp;
            for ($j = 1; $j < $iterations; $j++) {
                 $tmp  = hash_hmac($algo, $tmp, $password, true);
                 $res ^= $tmp;
            }
            $result .= $res;
        }
        $result = substr($result, 0, $length);
        return $raw_output ? $result : bin2hex($result);
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
