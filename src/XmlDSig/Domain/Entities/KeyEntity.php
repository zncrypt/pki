<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Entities;

class KeyEntity
{

    private $privateKey;
    private $privateKeyPassword;
    private $publicKey;
    private $certificate;
    private $p12;
    private $csr;

    public function getPrivateKey()
    {
        return $this->private;
    }

    public function setPrivateKey($privateKey): void
    {
        $this->private = $privateKey;
    }

    public function getPrivateKeyPassword()
    {
        return $this->privatePassword;
    }

    public function setPrivateKeyPassword($privateKeyPassword): void
    {
        $this->privatePassword = $privateKeyPassword;
    }

    public function getPublicKey()
    {
        return $this->public;
    }

    public function setPublicKey($publicKey): void
    {
        $this->public = $publicKey;
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