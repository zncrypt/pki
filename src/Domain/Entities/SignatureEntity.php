<?php

namespace ZnCrypt\Pki\Domain\Entities;

class SignatureEntity
{

    private $signatureBin;
    private $algorithm;

    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    public function setAlgorithm($algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    public function setSignatureBin($signature): void
    {
        $this->signatureBin = $signature;
    }

    public function setSignatureBase64($signature): void
    {
        $this->signatureBin = base64_decode($signature);
    }

    public function setSignatureHex($signature): void
    {
        $this->signatureBin = hex2bin($signature);
    }

    public function getSignatureBin()
    {
        return $this->signatureBin;
    }

    public function getSignatureBase64()
    {
        return base64_encode($this->signatureBin);
    }

    public function getSignatureHex()
    {
        return bin2hex($this->signatureBin);
    }
}
