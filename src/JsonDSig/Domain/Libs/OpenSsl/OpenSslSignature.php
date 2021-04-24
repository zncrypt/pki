<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\OpenSsl;

use phpseclib\File\X509;
use ZnCrypt\Base\Domain\Enums\OpenSslAlgoEnum;
use ZnCrypt\Base\Domain\Exceptions\CertificateExpiredException;
use ZnCrypt\Base\Domain\Exceptions\ExpiredException;
use ZnCrypt\Base\Domain\Exceptions\FailSignatureException;
use ZnCrypt\Base\Domain\Exceptions\InvalidDigestException;
use ZnCrypt\Base\Domain\Helpers\EncodingHelper;
use ZnCrypt\Pki\Domain\Helpers\RsaKeyHelper;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\JsonDSig\Domain\Entities\SignatureEntity;
use ZnCrypt\Pki\JsonDSig\Domain\Helpers\OpenSslHelper;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\C14n;
use ZnCrypt\Pki\X509\Domain\Helpers\X509Helper;

class OpenSslSignature
{

    private $keyStore;

    public function __construct(RsaStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    public function sign($data, SignatureEntity $signatureEntity)
    {
        $digestBinaryValue = $this->getDigest($data, $signatureEntity);
        $signatureMethod = OpenSslAlgoEnum::nameToOpenSsl($signatureEntity->getSignatureMethod());
        //$openSsl = new OpenSsl();
        $signatureBinaryValue = OpenSslHelper::sign($digestBinaryValue, $signatureMethod, $this->keyStore->getPrivateKey(), $this->keyStore->getPrivateKeyPassword());
        $digestValue = EncodingHelper::encode($digestBinaryValue, $signatureEntity->getDigestFormat());
        $signatureEntity->setDigestValue($digestValue);
        $signatureEntity->setSignatureValue(base64_encode($signatureBinaryValue));
        $certificate = RsaKeyHelper::keyToLine($this->keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
    }

    public function verify($data, SignatureEntity $signatureEntity)
    {
        $digestBinaryValue = $this->getDigest($data, $signatureEntity);
        $digestValue = EncodingHelper::encode($digestBinaryValue, $signatureEntity->getDigestFormat());
        if ($signatureEntity->getDigestValue() != $digestValue) {
            throw new InvalidDigestException();
        }
        $signatureMethod = OpenSslAlgoEnum::nameToOpenSsl($signatureEntity->getSignatureMethod());
        $signatureBinaryValue = base64_decode($signatureEntity->getSignatureValue());
        //$openSsl = new OpenSsl();

        $x509 = new X509();
//        $x509->loadCA(file_get_contents($this->rootCaFile));
        $certArray = $x509->loadX509($signatureEntity->getX509Certificate());

        if (!$x509->validateSignature()) {
            //throw new FailCertificateSignatureException();
        }
        if (!$x509->validateDate()) {
            throw new CertificateExpiredException('Certificate expired');
        }

//        $publicKey = $certArray['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
        $publicKey = X509Helper::extractPublicKey($signatureEntity->getX509Certificate());
        $isVerify = OpenSslHelper::verify($digestBinaryValue, $signatureBinaryValue, $signatureMethod, $publicKey);
        if(!$isVerify) {
            throw new FailSignatureException('Fail digest signature');
        }
        //return $isVerify;
    }

    private function getDigest($body, SignatureEntity $signatureEntity)
    {
        $c14n = new C14n(['sort-string', 'hex-string', 'json-unescaped-unicode']);
        $c14nData = $c14n->encode($body);
        return hash($signatureEntity->getDigestMethod(), $c14nData, true);
    }
}
