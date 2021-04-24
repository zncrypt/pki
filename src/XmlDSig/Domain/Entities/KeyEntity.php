<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Entities;

class KeyEntity
{

    private $private;
    private $public;
    private $certificate;
    private $p12;
    private $csr;

    public function getPrivate()
    {
        return $this->private;
    }

    public function setPrivate($private): void
    {
        $this->private = $private;
    }

    public function getPublic()
    {
        return $this->public;
    }

    public function setPublic($public): void
    {
        $this->public = $public;
    }

    public function getCertificate()
    {
        return $this->certificate;
    }

    public function setCertificate($certificate): void
    {
        $this->certificate = $certificate;
    }

    public function getP12()
    {
        return $this->p12;
    }

    public function setP12($p12): void
    {
        $this->p12 = $p12;
    }

    public function getCsr()
    {
        return $this->csr;
    }

    public function setCsr($csr): void
    {
        $this->csr = $csr;
    }
}