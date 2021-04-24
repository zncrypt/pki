<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\OpenSsl;

use BaconQrCode\Renderer\Color\Cmyk;
use BaconQrCode\Renderer\Color\Gray;
use BaconQrCode\Renderer\Color\Rgb;
use phpseclib\File\X509;
use ZnCrypt\Base\Domain\Enums\EncodingEnum;
use ZnCrypt\Base\Domain\Enums\OpenSslAlgoEnum;
use ZnCrypt\Base\Domain\Exceptions\CertificateExpiredException;
use ZnCrypt\Base\Domain\Exceptions\ExpiredException;
use ZnCrypt\Base\Domain\Exceptions\FailSignatureException;
use ZnCrypt\Base\Domain\Exceptions\InvalidDigestException;
use ZnCrypt\Base\Domain\Exceptions\UnknownEncodingException;
use ZnCrypt\Base\Domain\Helpers\EncodingHelper;
use ZnCrypt\Pki\Domain\Helpers\RsaKeyHelper;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\JsonDSig\Domain\Entities\SignatureEntity;
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
        $openSsl = new OpenSsl($this->keyStore);
        $signatureBinaryValue = $openSsl->signWithPrivateKey($digestBinaryValue, $signatureMethod, $this->keyStore->getPrivateKey(), $this->keyStore->getPrivateKeyPassword());
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
        if($signatureEntity->getDigestValue() != $digestValue) {
            throw new InvalidDigestException();
        }
        $signatureMethod = OpenSslAlgoEnum::nameToOpenSsl($signatureEntity->getSignatureMethod());
        $signatureBinaryValue = base64_decode($signatureEntity->getSignatureValue());
        $openSsl = new OpenSsl($this->keyStore);

        $x509 = new X509();
//        $x509->loadCA(file_get_contents($this->rootCaFile));
        $certArray = $x509->loadX509($signatureEntity->getX509Certificate());

        if (!$x509->validateSignature()) {
            //throw new FailSignatureException();
        }
        if (!$x509->validateDate()) {
            throw new CertificateExpiredException();
        }

//        $publicKey = $certArray['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'];
        $publicKey = X509Helper::extractPublicKey($signatureEntity->getX509Certificate());
        $isVerify = $openSsl->verifyWithPublicKey($digestBinaryValue, $signatureBinaryValue, $signatureMethod, $publicKey);
        return $isVerify;
    }

    private function getDigest($body, SignatureEntity $signatureEntity)
    {
        $c14n = new C14n(['sort-string', 'hex-string', 'json-unescaped-unicode']);
        $c14nData = $c14n->encode($body);
        return hash($signatureEntity->getDigestMethod(), $c14nData, true);
    }
}
