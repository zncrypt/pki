<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Entities;

class SignatureEntity
{

    private $digestMethod;
    private $digestFormat;
    private $digestValue;
    private $signatureMethod;
    private $signatureValue;
    private $x509Certificate;

    public function getDigestMethod()
    {
        return $this->digestMethod;
    }

    public function setDigestMethod($digestMethod): void
    {
        $this->digestMethod = $digestMethod;
    }

    public function getDigestFormat()
    {
        return $this->digestFormat;
    }

    public function setDigestFormat($digestFormat): void
    {
        $this->digestFormat = $digestFormat;
    }

    public function getDigestValue()
    {
        return $this->digestValue;
    }

    public function setDigestValue($digestValue): void
    {
        $this->digestValue = $digestValue;
    }

    public function getSignatureMethod()
    {
        return $this->signatureMethod;
    }

    public function setSignatureMethod($signatureMethod): void
    {
        $this->signatureMethod = $signatureMethod;
    }

    public function getSignatureValue()
    {
        return $this->signatureValue;
    }

    public function setSignatureValue($signatureValue): void
    {
        $this->signatureValue = $signatureValue;
    }

    public function getX509Certificate()
    {
        return $this->x509Certificate;
    }

    public function setX509Certificate($x509Certificate): void
    {
        $this->x509Certificate = $x509Certificate;
    }
}
