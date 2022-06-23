<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Libs;

use DOMDocument;
use Exception;
use phpseclib\Crypt\RSA;
use phpseclib\File\X509;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use ZnCore\Base\Format\Encoders\XmlEncoder;
use ZnCrypt\Pki\X509\Domain\Helpers\X509Helper;
use ZnCrypt\Pki\X509\Domain\Services\SignatureService;
use ZnCrypt\Pki\XmlDSig\Domain\Entities\FingerprintEntity;
use ZnCrypt\Pki\XmlDSig\Domain\Entities\HashEntity;
use ZnCrypt\Pki\XmlDSig\Domain\Entities\VerifyEntity;

class Signature
{

    private $x509;
    private $privateKey;
    private $publicKey;
    private $certificate;
    private $password;

    public function __construct()
    {
        $this->x509 = new X509();
    }

    public function setRootCa(string $ca)
    {
        $this->x509->loadCA($ca);
    }

    public function loadPrivateKey(string $privateKey, string $password = null)
    {
        $this->privateKey = $privateKey;
        if($password) {
            $this->password = $password;
        }
    }

    public function loadPublicKey(string $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function loadCertificate(string $certificate)
    {
        $this->certificate = $certificate;
    }

    public function publicKeyFingerprint($publicKey): FingerprintEntity
    {
//        $result = '-----BEGIN CERTIFICATE-----'.PHP_EOL;
//        $result .= $certificate.PHP_EOL;
//        $result .= '-----END CERTIFICATE-----';
//        //dd($certificate);
//        $certificateResource = openssl_x509_read(base64_decode($certificate));
//        $publicKey = openssl_get_publickey($certificateResource);

        $rsa = new RSA();
        $rsa->loadKey($publicKey);

        //dd($result);
        //$cert = openssl_x509_read(($result));
        $hashEntity = new FingerprintEntity();

        $hashEntity->setSha256($rsa->getPublicKeyFingerprint('sha256'));
        $hashEntity->setSha1($rsa->getPublicKeyFingerprint('sha1'));
        $hashEntity->setMd5($rsa->getPublicKeyFingerprint('md5'));
        return $hashEntity;
    }

    public function sign(string $sourceXml): string
    {
        $doc = new DOMDocument();
        $doc->loadXML($sourceXml);
        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        // Sign using SHA-256
        $objDSig->addReference(
            $doc,
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature']
        );

        // Create a new (private) Security key
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));

        //If key has a passphrase, set it using
        $objKey->passphrase = $this->password;

        // Load the private key
        $objKey->loadKey($this->privateKey, false);

        if($this->certificate) {
            $objDSig->add509Cert($this->certificate);
        }
        
        // Sign the XML file
        $objDSig->sign($objKey);

        // Append the signature to the XML
        $objDSig->appendSignature($doc->documentElement);
        // Save the signed XML
        $signedXml = $doc->saveXML();
        return $signedXml;
    }

    public function verify(string $xml): VerifyEntity
    {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($doc);
        if (!$objDSig) {
            throw new Exception("Cannot locate Signature Node");
        }
        $objXMLSecDSig->canonicalizeSignedInfo();

        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey) {
            throw new Exception("We have no idea about the key");
        }

        $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
        if (!$objKeyInfo->key) {
            if($this->publicKey) {
                $objKey->loadKey($this->publicKey);
            }
            if($this->certificate) {
                $objKey->loadKey($this->certificate, false, true);
            }
        }

        try {
            $isValidDigest = $objXMLSecDSig->validateReference();
        } catch (\Throwable $e) {
            $isValidDigest = false;
        }

        //$isValidX509 = $this->validateX509Cert($xml);

        $certContent = $this->extractCertificateFromXml($xml);
        $certArray = $this->x509->loadX509($certContent);

        $signatureService = new SignatureService($this->getRootNCa());
        $info = $signatureService->getInfo($xml);
        //dd($info);

        $verifyEntity = new VerifyEntity();
        $verifyEntity->setCertificateSignature($this->x509->validateSignature());

        $verifyEntity->setCertificateDate($this->x509->validateDate());
        $verifyEntity->setSignature($objXMLSecDSig->verify($objKey) === 1);
        $verifyEntity->setDigest($isValidDigest);
        $verifyEntity->setPerson($info->getPerson());
        $verifyEntity->setCertificateData($certArray);
//        dd($certArray['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']);
        $verifyEntity->setFingerprint($this->publicKeyFingerprint($certArray['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']));
        return $verifyEntity;
    }

    public function verifyCertificate($certContent): VerifyEntity
    {
        $certArray = $this->x509->loadX509($certContent);
        $certificateEntity = X509Helper::certArrayToEntity($certArray, $certContent);
        $verifyEntity = new VerifyEntity();
        $verifyEntity->setCertificateSignature($this->x509->validateSignature());
        $verifyEntity->setCertificateDate($this->x509->validateDate());
        //$verifyEntity->setPerson(X509Helper::createPersonEntity($certificateEntity->getSubject()));
        //dd($certArray);
        $verifyEntity->setFingerprint($this->publicKeyFingerprint($certArray['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']));
        $verifyEntity->setCertificateData($certArray);
        return $verifyEntity;
    }

    private function extractCertificateFromXml(string $xml)
    {
        $xmlEncoder = new XmlEncoder();
        $arr = $xmlEncoder->decode($xml);

//        $certContent = $arr['response']['ds:Signature']['ds:KeyInfo']['ds:X509Data']['ds:X509Certificate'];
        $certContent = $arr['root']['ds:Signature']['ds:KeyInfo']['ds:X509Data']['ds:X509Certificate'];
        return $certContent;
    }

    /*public function validateX509Cert(string $xml): bool
    {
        $certContent = $this->extractCertificateFromXml($xml);
        //dd($certContent);
        $certArray = $this->x509->loadX509($certContent);

        dd(json_encode($certArray, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

        return $this->x509->validateSignature();
    }*/

    private function getRootNCa(): string
    {
        $b64Cert = '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';
        return base64_decode($b64Cert);
    }
}
