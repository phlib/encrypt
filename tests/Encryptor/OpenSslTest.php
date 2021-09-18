<?php

namespace Phlib\Encrypt\Test\Encryptor;

use Phlib\Encrypt\Encryptor\OpenSsl;
use PHPUnit\Framework\TestCase;

class OpenSslTest extends TestCase
{
    /**
     * @var OpenSsl
     */
    protected $encryptor;

    public function setUp()
    {
        $this->encryptor = new OpenSsl('abc123');
    }

    public function testEncryptReturnsNonEmptyString()
    {
        $encrypted = $this->encryptor->encrypt('shoop di whoop');
        static::assertNotEmpty($encrypted);
    }

    public function testEncryptReturnsDifferentString()
    {
        $original = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);
        static::assertNotEquals($original, $encrypted);
    }

    public function testDecryptReturnsOriginal()
    {
        $original = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);
        $decrypted = $this->encryptor->decrypt($encrypted);
        static::assertEquals($original, $decrypted);
    }

    public function testEncryptReturnsUniqueOnMultipleCalls()
    {
        $original = 'shoop di whoop';
        $encrypted = [];
        $numberOfEncryptions = 10;
        for ($i = 0; $i < $numberOfEncryptions; $i++) {
            $encrypted[$this->encryptor->encrypt($original)] = true;
        }
        static::assertCount($numberOfEncryptions, $encrypted);
    }

    /**
     * @expectedException \Phlib\Encrypt\InvalidArgumentException
     * @expectedExceptionMessage Data is not valid
     */
    public function testDecryptFailsWithInsufficientData()
    {
        $this->encryptor->decrypt('meugghhh');
    }

    /**
     * @expectedException \Phlib\Encrypt\RuntimeException
     */
    public function testDecryptFailsWithGarbage()
    {
        $this->encryptor->decrypt(str_repeat('meugghhh', 20));
    }

    /**
     * @expectedException \Phlib\Encrypt\RuntimeException
     * @expectedExceptionMessage HMAC
     */
    public function testDecryptFailsWithModifiedData()
    {
        $original = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);

        $index = random_int(0, strlen($encrypted) - 1);
        $encryptedModified = substr($encrypted, 0, $index);
        $encryptedModified .= chr(ord(substr($encrypted, $index, 1)) + 1);
        $encryptedModified .= substr($encrypted, $index + 1);

        $this->encryptor->decrypt($encryptedModified);
    }

    /**
     * @expectedException \Phlib\Encrypt\RuntimeException
     * @expectedExceptionMessage Failed to decrypt data
     */
    public function testDecryptFailsWithUnencryptedData()
    {
        // This data has been built using correct HMAC, but the original data was not encrpyted
        // HMAC will pass, but openssl_decrypt() will fail
        $base64 = 'VzqOJoRMXkXT/1g3mZQ712LHXNKg5sIiVgB4zQZffOD3XOtW0yEOoRHcGheVbPMeC8N9TKRyKh1UaGlzIGRhdGEgaXMgbm90IGVuY3J5cHRlZA==';
        $notEncrypted = base64_decode($base64);

        $this->encryptor->decrypt($notEncrypted);
    }
}
