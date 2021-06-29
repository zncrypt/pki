<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Entities;

use ZnCrypt\Pki\X509\Domain\Entities\PersonEntity;

class VerifyEntity
{

    //private $certificate = false;
    private $certificateSignature = null;
    private $certificateDate = null;
    private $digest = null;
    private $signature = null;
    private $fingerprint;
    private $person;
    private $certificateData;

    /*public function isCertificate(): bool
    {
        return $this->certificateSignature;
    }

    public function setCertificate(bool $certificate): void
    {
        $this->certificateSignature = $certificate;
    }*/

    public function isCertificateSignature(): ?bool
    {
        return $this->certificateSignature;
    }

    public function setCertificateSignature(bool $certificateSignature): void
    {
        $this->certificateSignature = $certificateSignature;
    }

    public function isCertificateDate(): ?bool
    {
        return $this->certificateDate;
    }

    public function setCertificateDate(bool $certificateDate): void
    {
        $this->certificateDate = $certificateDate;
    }

    public function isDigest(): ?bool
    {
        return $this->digest;
    }

    public function setDigest(bool $digest): void
    {
        $this->digest = $digest;
    }

    public function isSignature(): ?bool
    {
        return $this->signature;
    }

    public function setSignature(bool $signature): void
    {
        $this->signature = $signature;
    }

    public function getFingerprint(): ?FingerprintEntity
    {
        return $this->fingerprint;
    }

    public function setFingerprint(FingerprintEntity $fingerprint): void
    {
        $this->fingerprint = $fingerprint;
    }

    public function isVerify(): bool
    {
        return $this->isDigest() && $this->isCertificateSignature() && $this->isCertificateDate() && $this->isSignature();
    }

    public function getPerson(): ?PersonEntity
    {
        return $this->person;
    }

    public function setPerson(PersonEntity $person): void
    {
        $this->person = $person;
    }

    public function getCertificateData(): array
    {
        return $this->certificateData;
    }

    public function setCertificateData(array $certificateData): void
    {
        $this->certificateData = $certificateData;
    }
}