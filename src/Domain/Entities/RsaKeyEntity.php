<?php

namespace ZnCrypt\Pki\Domain\Entities;

use ZnCrypt\Pki\Domain\Helpers\RsaKeyHelper;

class RsaKeyEntity
{

    const PUBLIC_KEY = 'PUBLIC KEY';
    const PRIVATE_KEY = 'PRIVATE KEY';
    const CERTIFICATE = 'CERTIFICATE';

    private $raw;
    private $type;

    public function __construct(string $type, string $raw = null)
    {
        $this->type = $type;
        if($raw) {
            $this->raw = $raw;
        }
    }

    public function getPem(): string
    {
        return RsaKeyHelper::binToPem($this->raw, $this->type);
    }

    public function setPem(string $pem): void
    {
        $this->raw = RsaKeyHelper::pemToBin($pem);
    }

    public function getBase64(): string
    {
        return base64_encode($this->raw);
    }

    public function setBase(string $base64): void
    {
        $this->raw = base64_decode($base64);
    }

    public function getRaw(): string
    {
        return $this->raw;
    }

    public function setRaw(string $raw): void
    {
        $this->raw = $raw;
    }

    public function getType()
    {
        return $this->type;
    }

    /*public function setType($type): void
    {
        $this->type = $type;
    }*/

}
