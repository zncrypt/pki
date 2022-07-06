<?php

namespace ZnCrypt\Pki\X509\Domain\Entities;


use ZnCore\Text\Helpers\TextHelper;
use ZnCrypt\Pki\Domain\Helpers\RsaKeyHelper;

class SignatureEntity
{

    private $digest;
    private $signature;
    private $certificate;

    public function getDigest()
    {
        return $this->digest;
    }

    public function setDigest($digest): void
    {
        $this->digest = $digest;
    }

    public function getSignature()
    {
        return $this->signature;
    }

    public function setSignature($signature): void
    {
        $this->signature = $signature;
    }

    public function getCertificate()
    {
        return $this->certificate;
    }

    public function getCertificatePemFormat() :string
    {
        $certificate = TextHelper::removeAllSpace($this->certificate);
        return RsaKeyHelper::base64ToPem($certificate, 'CERTIFICATE');
    }

    public function setCertificate(string $certificate): void
    {
        $this->certificate = $certificate;
    }
}
