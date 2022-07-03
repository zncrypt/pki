<?php

namespace ZnCrypt\Pki\X509\Domain\Entities;

use phpseclib\Math\BigInteger;
use DateTime;

class CertificateEntity
{

    private $version;
    private $serialNumber;
    private $issuer;
    private $subject;
    private $publicKey;
    private $certificate;
    private $extensions;
    private $authorityInfo;
    private $signature;
    private $createdAt;
    private $expiredAt;

    /**
     * @return mixed
     */
    public function getVersion(): string
    {
        return $this->version;
    }

    /**
     * @param mixed $version
     */
    public function setVersion(string $version): void
    {
        $this->version = $version;
    }

    /**
     * @return mixed
     */
    public function getSerialNumber(): BigInteger
    {
        return $this->serialNumber;
    }

    /**
     * @param mixed $serialNumber
     */
    public function setSerialNumber(BigInteger $serialNumber): void
    {
        $this->serialNumber = $serialNumber;
    }

    /**
     * @return mixed
     */
    public function getIssuer()
    {
        return $this->issuer;
    }

    /**
     * @param mixed $issuer
     */
    public function setIssuer($issuer): void
    {
        $this->issuer = $issuer;
    }

    /**
     * @return mixed
     */
    public function getSubject()
    {
        return $this->subject;
    }

    /**
     * @param mixed $subject
     */
    public function setSubject($subject): void
    {
        $this->subject = $subject;
    }

    /**
     * @return mixed
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * @param mixed $publicKey
     */
    public function setPublicKey(string $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @return mixed
     */
    public function getCertificate(): string
    {
        return $this->certificate;
    }

    /**
     * @param mixed $certificate
     */
    public function setCertificate(string $certificate): void
    {
        $this->certificate = $certificate;
    }

    /**
     * @return mixed
     */
    public function getExtensions()
    {
        return $this->extensions;
    }

    /**
     * @param mixed $extensions
     */
    public function setExtensions($extensions): void
    {
        $this->extensions = $extensions;
    }

    /**
     * @return mixed
     */
    public function getAuthorityInfo()
    {
        return $this->authorityInfo;
    }

    /**
     * @param mixed $authorityInfo
     */
    public function setAuthorityInfo($authorityInfo): void
    {
        $this->authorityInfo = $authorityInfo;
    }

    /**
     * @return mixed
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @param mixed $signature
     */
    public function setSignature($signature): void
    {
        $this->signature = $signature;
    }

    /**
     * @return mixed
     */
    public function getCreatedAt(): DateTime
    {
        return $this->createdAt;
    }

    /**
     * @param mixed $createdAt
     */
    public function setCreatedAt(DateTime $createdAt): void
    {
        $this->createdAt = $createdAt;
    }

    /**
     * @return mixed
     */
    public function getExpiredAt(): DateTime
    {
        return $this->expiredAt;
    }

    /**
     * @param mixed $expiredAt
     */
    public function setExpiredAt(DateTime $expiredAt): void
    {
        $this->expiredAt = $expiredAt;
    }

}
