<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Entities;

class FingerprintEntity
{

    private $md5;
    private $sha1;
    private $sha256;

    public function getMd5()
    {
        return $this->md5;
    }

    public function setMd5($md5): void
    {
        $this->md5 = $md5;
    }

    public function getSha1()
    {
        return $this->sha1;
    }

    public function setSha1($sha1): void
    {
        $this->sha1 = $sha1;
    }

    public function getSha256()
    {
        return $this->sha256;
    }

    public function setSha256($sha256): void
    {
        $this->sha256 = $sha256;
    }
    
}
