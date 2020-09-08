<?php

namespace ZnCrypt\Pki\Domain\Entities;

class CertificateEntity
{

    private $subject;
    private $issuer;
    private $signature;

    public function getSubject(): CertificateSubjectEntity
    {
        return $this->subject;
    }

    public function setSubject(CertificateSubjectEntity $subject): void
    {
        $this->subject = $subject;
    }

    public function getIssuer()
    {
        return $this->issuer;
    }

    public function setIssuer($issuer): void
    {
        $this->issuer = $issuer;
    }

    public function getSignature(): SignatureEntity
    {
        return $this->signature;
    }

    public function setSignature(SignatureEntity $signature): void
    {
        $this->signature = $signature;
    }

}
