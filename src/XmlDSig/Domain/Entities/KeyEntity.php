<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Entities;

class KeyEntity
{

    private $private;
    private $public;
    private $certificate;
    private $p12;

    /**
     * @return mixed
     */
    public function getPrivate()
    {
        return $this->private;
    }

    /**
     * @param mixed $private
     */
    public function setPrivate($private): void
    {
        $this->private = $private;
    }

    /**
     * @return mixed
     */
    public function getPublic()
    {
        return $this->public;
    }

    /**
     * @param mixed $public
     */
    public function setPublic($public): void
    {
        $this->public = $public;
    }

    /**
     * @return mixed
     */
    public function getCertificate()
    {
        return $this->certificate;
    }

    /**
     * @param mixed $certificate
     */
    public function setCertificate($certificate): void
    {
        $this->certificate = $certificate;
    }

    /**
     * @return mixed
     */
    public function getP12()
    {
        return $this->p12;
    }

    /**
     * @param mixed $p12
     */
    public function setP12($p12): void
    {
        $this->p12 = $p12;
    }

}