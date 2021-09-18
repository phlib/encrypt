<?php

declare(strict_types=1);

namespace Phlib\Encrypt\Encryptor;

use Phlib\Encrypt\EncryptorInterface;
use Phlib\Encrypt\InvalidArgumentException;
use Phlib\Encrypt\RuntimeException;

final class OpenSsl implements EncryptorInterface
{
    private const CIPHER_METHOD = 'aes-256-cbc';

    private const PBKDF2_ITERATIONS = 50000;

    private const SALT_LENGTH = 8;

    private const MAC_LENGTH = 32; // strlen(hash_hmac('sha256', '', '', true))

    private const KEY_LENGTH = 16; // 128 bits

    private string $password;

    private int $ivLength; // determined from cipher method

    public function __construct(string $password)
    {
        $this->password = $password;
        $this->ivLength = \openssl_cipher_iv_length(self::CIPHER_METHOD);
    }

    public function encrypt(string $data): string
    {
        $salt = \random_bytes(self::SALT_LENGTH);
        $iv = \random_bytes($this->ivLength);

        [$encKey, $authKey] = $this->deriveKeys($salt);

        $encryptedData = \openssl_encrypt($data, self::CIPHER_METHOD, $encKey, OPENSSL_RAW_DATA, $iv);
        $mac = \hash_hmac('sha256', $encryptedData . $iv, $authKey, true);

        return $salt . $iv . $mac . $encryptedData;
    }

    public function decrypt(string $data): string
    {
        if (\strlen($data) < self::SALT_LENGTH + $this->ivLength + self::MAC_LENGTH) {
            throw new InvalidArgumentException('Data is not valid for decryption');
        }
        $salt = \substr($data, 0, self::SALT_LENGTH);
        $iv = \substr($data, self::SALT_LENGTH, $this->ivLength);
        $mac = \substr($data, self::SALT_LENGTH + $this->ivLength, self::MAC_LENGTH);
        $encryptedData = \substr($data, self::SALT_LENGTH + $this->ivLength + self::MAC_LENGTH);

        [$encKey, $authKey] = $this->deriveKeys($salt);

        $calculatedMac = \hash_hmac('sha256', $encryptedData . $iv, $authKey, true);

        if (!\hash_equals($calculatedMac, $mac)) {
            throw new RuntimeException('HMAC failed to match');
        }

        $decryptedData = \openssl_decrypt($encryptedData, self::CIPHER_METHOD, $encKey, OPENSSL_RAW_DATA, $iv);

        if ($decryptedData === false) {
            throw new RuntimeException('Failed to decrypt data');
        }

        return $decryptedData;
    }

    /**
     * Derive the keys for encryption and authentication using the given salt, and the password
     */
    private function deriveKeys(string $salt): array
    {
        $key = \hash_pbkdf2('sha256', $this->password, $salt, self::PBKDF2_ITERATIONS, self::KEY_LENGTH * 2, true);

        return \str_split($key, self::KEY_LENGTH);
    }
}
