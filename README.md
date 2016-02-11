# phlib/encrypt

[![Build Status](https://img.shields.io/travis/phlib/encrypt/master.svg?style=flat-square)](https://travis-ci.org/phlib/encrypt)

PHP encryption/decryption tool

## Usage

Creation of an encryptor

``` php
$encryptor = new \Phlib\Encrypt\Encryptor\OpenSsl($encryptionPassword);

```

The encryption password should be a random string of data, preferably at least 32 bytes long, and should be stored on the server.
For example, this could be a  configuration value or constant (perhaps base64 encoded depending on how the value needs to be stored).
 
The same encryption password must be used to decrypt as was used to encrypt.

Example of creating an encryption password

``` php 
$encryptionPassword = openssl_random_pseudo_bytes(32);

```

Encrypt/decrypt some data

``` php
$encryptor = new \Phlib\Encrypt\Encryptor\OpenSsl($encryptionPassword);
$myData    = 'some sensitive data which needs encrypting';

$encrypted = $encryptor->encrypt($myData);

// $encryptor could be a completely different instance here,
// so long as it is initialised with the same encryption password
$decrypted = $encryptor->decrypt(encrypted);

```
