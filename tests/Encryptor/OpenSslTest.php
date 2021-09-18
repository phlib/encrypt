<?php

declare(strict_types=1);

namespace Phlib\Encrypt\Test\Encryptor;

use Phlib\Encrypt\Encryptor\OpenSsl;
use Phlib\Encrypt\InvalidArgumentException;
use Phlib\Encrypt\RuntimeException;
use PHPUnit\Framework\TestCase;

class OpenSslTest extends TestCase
{
    private OpenSsl $encryptor;

    protected function setUp(): void
    {
        $this->encryptor = new OpenSsl('abc123');
    }

    public function testEncryptReturnsNonEmptyString(): void
    {
        $encrypted = $this->encryptor->encrypt('shoop di whoop');
        static::assertNotEmpty($encrypted);
    }

    public function testEncryptReturnsDifferentString(): void
    {
        $original = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);
        static::assertNotSame($original, $encrypted);
    }

    public function testDecryptReturnsOriginal(): void
    {
        $original = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);
        $decrypted = $this->encryptor->decrypt($encrypted);
        static::assertSame($original, $decrypted);
    }

    public function testEncryptReturnsUniqueOnMultipleCalls(): void
    {
        $original = 'shoop di whoop';
        $encrypted = [];
        $numberOfEncryptions = 10;
        for ($i = 0; $i < $numberOfEncryptions; $i++) {
            $encrypted[$this->encryptor->encrypt($original)] = true;
        }
        static::assertCount($numberOfEncryptions, $encrypted);
    }

    public function testDecryptFailsWithInsufficientData(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Data is not valid');

        $this->encryptor->decrypt('meugghhh');
    }

    public function testDecryptFailsWithGarbage(): void
    {
        $this->expectException(RuntimeException::class);

        $this->encryptor->decrypt(str_repeat('meugghhh', 20));
    }

    public function testDecryptFailsWithModifiedData(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('HMAC');

        $original = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);

        $index = random_int(0, strlen($encrypted) - 1);
        $encryptedModified = substr($encrypted, 0, $index);
        $encryptedModified .= chr(ord(substr($encrypted, $index, 1)) + 1);
        $encryptedModified .= substr($encrypted, $index + 1);

        $this->encryptor->decrypt($encryptedModified);
    }

    public function testDecryptFailsWithUnencryptedData(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Failed to decrypt data');

        // This data has been built using correct HMAC, but the original data was not encrpyted
        // HMAC will pass, but openssl_decrypt() will fail
        $base64 = 'VzqOJoRMXkXT/1g3mZQ712LHXNKg5sIiVgB4zQZffOD3XOtW0yEOoRHcGheVbPMeC8N9TKRyKh1UaGlzIGRhdGEgaXMgbm90IGVuY3J5cHRlZA==';
        $notEncrypted = base64_decode($base64, true);

        $this->encryptor->decrypt($notEncrypted);
    }
}
