<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

use ZnCrypt\Base\Domain\Enums\OpenSslAlgoEnum;
use ZnCrypt\Pki\Domain\Helpers\RsaKeyHelper;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\JsonDSig\Domain\Entities\SignatureEntity;

class OpenSslSignature
{

    private $keyStore;

    public function __construct(RsaStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    public function sign($data, SignatureEntity $signatureEntity)
    {
        $digestValue = $this->getDigest($data, $signatureEntity->getDigestMethod());
        $signatureMethod = OpenSslAlgoEnum::nameToOpenSsl($signatureEntity->getSignatureMethod());
        $openSsl = new OpenSsl($this->keyStore);
        $signatureBinaryValue = $openSsl->sign($digestValue, $signatureMethod);
        $signatureEntity->setDigestValue($digestValue);
        $signatureEntity->setSignatureValue(base64_encode($signatureBinaryValue));
        $certificate = RsaKeyHelper::keyToLine($this->keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
    }

    public function verify($data, SignatureEntity $signatureEntity)
    {
        $dataDigest = $this->getDigest($data, $signatureEntity->getDigestMethod());
        $signatureMethod = OpenSslAlgoEnum::nameToOpenSsl($signatureEntity->getSignatureMethod());
        $signatureBinaryValue = base64_decode($signatureEntity->getSignatureValue());
        $openSsl = new OpenSsl($this->keyStore);
        $isVerify = $openSsl->verify($dataDigest, $signatureBinaryValue, $signatureMethod);
        return $isVerify;
    }

    private function getDigest($body, string $digestMethod)
    {
        $c14n = new C14n(['sort-string', 'hex-string', 'json-unescaped-unicode']);
        $c14nData = $c14n->encode($body);
        $dataDigest = hash($digestMethod, $c14nData);
        return $dataDigest;
    }
}
