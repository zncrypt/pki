<?php

namespace ZnCrypt\Pki\X509\Domain\Services;

use phpseclib\File\X509;
use phpseclib\Crypt\RSA;
use ZnCore\Arr\Helpers\ArrayHelper;
use ZnCrypt\Pki\X509\Domain\Entities\CertificateEntity;
use ZnCrypt\Pki\X509\Domain\Entities\InfoEntity;
use ZnCrypt\Pki\X509\Domain\Entities\PersonEntity;
use ZnCrypt\Pki\X509\Domain\Entities\SignatureEntity;
use ZnCrypt\Pki\X509\Domain\Helpers\NcaLayerHelper;
use ZnCrypt\Pki\X509\Domain\Helpers\X509Helper;
use ZnCrypt\Pki\X509\Domain\Helpers\XmlHelper;
use DateTime;

class SignatureService
{

    private $x509;

    public function __construct(string $ca)
    {
        $this->x509 = new X509();
        $this->x509->loadCA($ca);
//        $certArray = $this->x509->loadX509($ca);
//        dd($certArray);
    }

    public function getInfo(string $xml): InfoEntity
    {
//        dd(X509Helper::getCertFromDomain('google.com'));

        $infoEntity = new InfoEntity();
        $signatureEntity = NcaLayerHelper::parseXmlSignature($xml);
        $certArray = $this->x509->loadX509($signatureEntity->getCertificatePemFormat());
        $certificateEntity = X509Helper::certArrayToEntity($certArray, $signatureEntity->getCertificatePemFormat());

        //dd($certificateEntity);
        $infoEntity->setPerson(X509Helper::createPersonEntity($certificateEntity->getSubject()));
        $infoEntity->setCertificate($certificateEntity);
//        $infoEntity->setPerson(X509Helper::parsePerson($certArray));
        $infoEntity->setIsAuthenticCertificate($this->x509->validateSignature());
        $pubKey = $certArray['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
        $infoEntity->setIsAuthenticSignature($this->isVerifySignature($pubKey, $signatureEntity));
        $infoEntity->setSignature($signatureEntity);
        return $infoEntity;
    }

    public function check(InfoEntity $infoEntity)
    {
        if( ! $infoEntity->getIsAuthenticCertificate()) {
            throw new \Exception('Certificate signature not verified!');
        }
        if( ! $infoEntity->getIsAuthenticSignature()) {
            //throw new \Exception('Content signature not verified!');
        }
    }

    private function isVerifySignature(string $pubKey, SignatureEntity $signatureEntity): bool
    {
        $plaintext = base64_decode($signatureEntity->getDigest());
        $signature = base64_decode($signatureEntity->getSignature());

//        $pubkeyid = openssl_get_publickey($pubKey);
//        $keyData = openssl_pkey_get_details($pubkeyid);
//        return openssl_verify($plaintext, $signature, $pubkeyid, OPENSSL_ALGO_SHA256);

        $rsa = new RSA();
        $rsa->loadKey($pubKey);
        $rsa->setHash('sha256');
//        dump($rsa->getPublicKey());
//        $rsa->loadKey($rsa->getPublicKey());
//        dd($pubKey);
//        $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
//        $rsa->setEncryptionMode(RSA::ENCRYPTION_NONE);
//        $rsa->setPublicKey($pubKey, RSA::PUBLIC_FORMAT_PKCS1);
        return $rsa->verify($plaintext, $signature);
    }
}
