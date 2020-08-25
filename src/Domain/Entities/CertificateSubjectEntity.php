<?php

namespace PhpBundle\Kpi\Domain\Entities;

use PhpBundle\Kpi\Domain\Helpers\RsaKeyHelper;

class CertificateSubjectEntity
{

    private $type;
    private $name;
    private $host;
    private $roles;
private $trustLevel;
    private $createdAt;
    private $expireAt;
    private $publicKey;

    public function __construct()
    {
        $this->createdAt = time();
    }

    public function getType()
    {
        return $this->type;
    }

    public function setType($type): void
    {
        $this->type = $type;
    }

    public function getName()
    {
        return $this->name;
    }

    public function setName($name): void
    {
        $this->name = $name;
    }

    public function getHost()
    {
        return $this->host;
    }

    public function setHost($host): void
    {
        $this->host = $host;
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function setRoles($roles): void
    {
        $this->roles = $roles;
    }

    public function getTrustLevel()
    {
        return $this->trustLevel;
    }

    public function setTrustLevel($trustLevel): void
    {
        $this->trustLevel = $trustLevel;
    }

    public function getCreatedAt()
    {
        return $this->createdAt;
    }

    public function setCreatedAt($createdAt): void
    {
        $this->createdAt = $createdAt;
    }

    public function getExpireAt()
    {
        return $this->expireAt;
    }

    public function setExpireAt($expireAt): void
    {
        $this->expireAt = $expireAt;
    }

    public function setExpire(int $seconds): void
    {
        $this->expireAt = $this->createdAt + $seconds;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function setPublicKey(string $publicKey): void
    {
        $this->publicKey = RsaKeyHelper::keyToLine($publicKey);
    }

}
