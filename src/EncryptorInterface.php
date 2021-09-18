<?php

declare(strict_types=1);

namespace Phlib\Encrypt;

interface EncryptorInterface
{
    public function encrypt(string $data): string;

    public function decrypt(string $data): string;
}
