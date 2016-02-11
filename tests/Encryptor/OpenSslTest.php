<?php

namespace library\Phlib\Encrypt\Test\Encryptor;

use Phlib\Encrypt\Encryptor\OpenSsl;

class OpenSslTest extends \PHPUnit_Framework_TestCase
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
        $this->assertNotEmpty($encrypted);
    }

    public function testEncryptReturnsDifferentString()
    {
        $original  = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);
        $this->assertNotEquals($original, $encrypted);
    }

    public function testDecryptReturnsOriginal()
    {
        $original  = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);
        $decrypted = $this->encryptor->decrypt($encrypted);
        $this->assertEquals($original, $decrypted);
    }

    public function testEncryptReturnsUniqueOnMultipleCalls()
    {
        $original  = 'shoop di whoop';
        $encrypted = [];
        $numberOfEncryptions = 10;
        for ($i = 0; $i < $numberOfEncryptions; $i++) {
            $encrypted[$this->encryptor->encrypt($original)] = true;
        }
        $this->assertEquals($numberOfEncryptions, count($encrypted));
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
        $this->encryptor->decrypt(str_repeat('meugghhh',20));
    }

    /**
     * @expectedException \Phlib\Encrypt\RuntimeException
     * @expectedExceptionMessage HMAC
     */
    public function testDecryptFailsWithModifiedData()
    {
        $original  = 'shoop di whoop';
        $encrypted = $this->encryptor->encrypt($original);

        $index = mt_rand(0, strlen($encrypted) - 1);
        $encryptedModified  = substr($encrypted, 0, $index);
        $encryptedModified .= chr(ord(substr($encrypted, $index, 1)) + 1);
        $encryptedModified .= substr($encrypted, $index + 1);

        $this->encryptor->decrypt($encryptedModified);
    }
}
