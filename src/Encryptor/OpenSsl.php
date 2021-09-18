<?php

namespace Phlib\Encrypt\Encryptor;

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

    /**
     * @var int
     */
    protected $ivLength; // dependant on cipher method

    /**
     * @var int
     */
    protected $macLength = 32; // strlen(hash_hmac('sha256', '', '', true))

    /**
     * @var int
     */
    protected $keyLength = 16; // 128 bits

    /**
     * OpenSsl constructor
     *
     * @param string $password
     */
    public function __construct($password)
    {
        $this->password = $password;
        $this->ivLength = \openssl_cipher_iv_length($this->cipherMethod);
    }

    /**
     * @param string $data
     * @return string
     */
    public function encrypt($data)
    {
        $salt = \random_bytes($this->saltLength);
        $iv = \random_bytes($this->ivLength);

        [$encKey, $authKey] = $this->deriveKeys($salt);

        $encryptedData = \openssl_encrypt($data, $this->cipherMethod, $encKey, OPENSSL_RAW_DATA, $iv);
        $mac = \hash_hmac('sha256', $encryptedData . $iv, $authKey, true);

        return $salt . $iv . $mac . $encryptedData;
    }

    /**
     * @param string $data
     * @return string
     */
    public function decrypt($data)
    {
        if (\strlen($data) < $this->saltLength + $this->ivLength + $this->macLength) {
            throw new InvalidArgumentException('Data is not valid for decryption');
        }
        $salt = \substr($data, 0, $this->saltLength);
        $iv = \substr($data, $this->saltLength, $this->ivLength);
        $mac = \substr($data, $this->saltLength + $this->ivLength, $this->macLength);
        $encryptedData = \substr($data, $this->saltLength + $this->ivLength + $this->macLength);

        [$encKey, $authKey] = $this->deriveKeys($salt);

        $calculatedMac = \hash_hmac('sha256', $encryptedData . $iv, $authKey, true);

        if (!\hash_equals($calculatedMac, $mac)) {
            throw new RuntimeException('HMAC failed to match');
        }

        $decryptedData = \openssl_decrypt($encryptedData, $this->cipherMethod, $encKey, OPENSSL_RAW_DATA, $iv);

        if ($decryptedData === false) {
            throw new RuntimeException('Failed to decrypt data');
        }

        return $decryptedData;
    }

    /**
     * Derive the keys for encryption and authentication using the given salt, and the password
     *
     * @param string $salt
     * @return array
     */
    protected function deriveKeys($salt)
    {
        $key = \hash_pbkdf2('sha256', $this->password, $salt, $this->pbkdf2Iterations, $this->keyLength * 2, true);

        return \str_split($key, $this->keyLength);
    }
}
