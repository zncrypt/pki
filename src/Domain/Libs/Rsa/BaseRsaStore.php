<?php

namespace ZnCrypt\Pki\Domain\Libs\Rsa;

use ZnCrypt\Pki\Domain\Entities\CertificateSubjectEntity;
use ZnCrypt\Pki\Domain\Enums\CertificateFormatEnum;
use ZnCrypt\Pki\Domain\Enums\RsaKeyFormatEnum;
use ZnCrypt\Base\Domain\Libs\Encoders\EncoderInterface;
use ZnCrypt\Pki\Domain\Helpers\RsaKeyHelper;
use ZnCore\Entity\Helpers\EntityHelper;

use ZnCore\Base\Arr\Helpers\ArrayHelper;

abstract class BaseRsaStore implements RsaStoreInterface
{

    const PRIVATE_KEY_FILE = 'priv.rsa';
    const PUBLIC_KEY_FILE = 'pub.rsa';
    const CERTIFICATE_FILE = 'cert.pem';
    const SUBJECT_FILE = 'subject.json';

    protected $readOnly = true;
    protected $p12 = null;
    protected $privateKeyPassword = null;

    public function enableWrite() {
        $this->readOnly = false;
    }

    public function setSubject(CertificateSubjectEntity $subject) {
        $array = EntityHelper::toArray($subject);
        $array = ArrayHelper::extractByKeys($array, [
            'type',
            'name',
            'host',
            'trustLevel',
        ]);
        $json = json_encode($array);
        $this->setContent(self::SUBJECT_FILE, $json);
    }

    public function getSubject(): CertificateSubjectEntity {
        $json = $this->getContent(self::SUBJECT_FILE);
        $array = json_decode($json, true);
        $subject = new CertificateSubjectEntity;
        EntityHelper::setAttributes($subject, $array);
        return $subject;
    }

    public function setCertificate(string $cert, string $format = CertificateFormatEnum::JSON) {
        $this->setContent(self::CERTIFICATE_FILE, $cert);
    }

    public function getCertificate(string $format = CertificateFormatEnum::JSON)
    {
        $key = $this->getContent(self::CERTIFICATE_FILE);
        /*if($format == CertificateFormatEnum::JSON) {
            $key = openssl_pkey_get_public($key);
        } elseif($format == CertificateFormatEnum::ARRAY) {
            $key = json_decode($key);
        }*/
        return $key;
    }

    public function setPublicKey(string $cert) {
        $this->setContent(self::PUBLIC_KEY_FILE, $cert);
    }

    public function getPublicKey(string $format = RsaKeyFormatEnum::TEXT)
    {
        $key = $this->getContent(self::PUBLIC_KEY_FILE);
        if($format == RsaKeyFormatEnum::BIN) {
            //$key = openssl_pkey_get_public($key);
            $key = RsaKeyHelper::pemToBin($key);
        } elseif($format == RsaKeyFormatEnum::PEM) {
            $key = RsaKeyHelper::base64ToPem($key, 'PUBLIC KEY');
        } else {
            $key = RsaKeyHelper::keyToLine($key);
        }
        return $key;
    }

    public function setPrivateKey(string $cert) {
        $this->setContent(self::PRIVATE_KEY_FILE, $cert);
    }

    public function getPrivateKey(string $format = RsaKeyFormatEnum::TEXT)
    {
        $key = $this->getContent(self::PRIVATE_KEY_FILE);
        if($format == RsaKeyFormatEnum::BIN) {
            $key = RsaKeyHelper::pemToBin($key);
            //$ogp = openssl_get_privatekey($this->privateKey);
        } elseif($format == RsaKeyFormatEnum::PEM) {
            $key = RsaKeyHelper::base64ToPem($key, 'PRIVATE KEY');
            //dd($key);
        } else {
            //$key = $this->keyToLine($key);
        }
        return $key;
    }

    public function getP12()
    {
        return $this->p12;
    }

    public function setP12($p12): void
    {
        $this->p12 = $p12;
    }

    public function getPrivateKeyPassword()
    {
        return $this->privateKeyPassword;
    }

    public function setPrivateKeyPassword($privateKeyPassword): void
    {
        $this->privateKeyPassword = $privateKeyPassword;
    }
}
