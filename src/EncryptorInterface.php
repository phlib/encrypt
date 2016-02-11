<?php

namespace Phlib\Encrypt;

interface EncryptorInterface
{

    /**
     * @param string $data
     * @return string
     */
    public function encrypt($data);

    /**
     * @param string $data
     * @return string
     */
    public function decrypt($data);

}
