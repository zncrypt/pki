<?php

namespace ZnCrypt\Pki\X509\Domain\Entities;

use ZnCore\Base\Helpers\StringHelper;

class InfoEntity
{

    private $person;
    private $certificate;
    private $signature;
    private $isAuthenticCertificate;
    private $isAuthenticSignature;

    public function getPerson(): PersonEntity
    {
        return $this->person;
    }

    public function setPerson(PersonEntity $person): void
    {
        $this->person = $person;
    }

    public function getCertificate(): CertificateEntity
    {
        return $this->certificate;
    }

    public function setCertificate(CertificateEntity $certificate): void
    {
        $this->certificate = $certificate;
    }

    public function getSignature()
    {
        return $this->signature;
    }

    public function setSignature($signature): void
    {
        $this->signature = $signature;
    }

    public function getIsAuthenticCertificate(): bool
    {
        return $this->isAuthenticCertificate;
    }

    public function setIsAuthenticCertificate(bool $isAuthenticCertificate): void
    {
        $this->isAuthenticCertificate = $isAuthenticCertificate;
    }

    public function getIsAuthenticSignature(): bool
    {
        return $this->isAuthenticSignature;
    }

    public function setIsAuthenticSignature(bool $isAuthenticSignature): void
    {
        $this->isAuthenticSignature = $isAuthenticSignature;
    }

}
