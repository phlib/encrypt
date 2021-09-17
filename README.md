# phlib/encrypt

[![Code Checks](https://img.shields.io/github/workflow/status/phlib/encrypt/CodeChecks?logo=github)](https://github.com/phlib/encrypt/actions/workflows/code-checks.yml)
[![Codecov](https://img.shields.io/codecov/c/github/phlib/encrypt.svg?logo=codecov)](https://codecov.io/gh/phlib/encrypt)
[![Latest Stable Version](https://img.shields.io/packagist/v/phlib/encrypt.svg?logo=packagist)](https://packagist.org/packages/phlib/encrypt)
[![Total Downloads](https://img.shields.io/packagist/dt/phlib/encrypt.svg?logo=packagist)](https://packagist.org/packages/phlib/encrypt)
![Licence](https://img.shields.io/github/license/phlib/encrypt.svg)

PHP encryption/decryption tool


## Install

Via Composer

``` bash
$ composer require phlib/encrypt
```

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
$encryptionPassword = \openssl_random_pseudo_bytes(32);

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

## License

This package is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
