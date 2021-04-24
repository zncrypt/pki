<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\OpenSsl;

use ZnCrypt\Pki\Domain\Enums\RsaKeyFormatEnum;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\JsonDSig\Domain\Helpers\OpenSslHelper;

class OpenSsl
{

    private $keyStore;

    public function __construct(RsaStoreInterface $keyStore = null)
    {
        $this->keyStore = $keyStore;
    }

    public function sign(string $digestBinaryValue, int $signatureMethod): string
    {
        $signatureBinaryValue = OpenSslHelper::sign($digestBinaryValue, $signatureMethod, $this->keyStore->getPrivateKey(), $this->keyStore->getPrivateKeyPassword());
//        $resource = openssl_pkey_get_private($this->keyStore->getPrivateKey(), $this->keyStore->getPrivateKeyPassword());
//        openssl_sign($digestBinaryValue, $signatureBinaryValue, $resource, $signatureMethod);
//        openssl_free_key($resource);
        return $signatureBinaryValue;
    }

    public function verify(string $digestBinaryValue, string $signatureBinaryValue, int $signatureMethod): bool
    {
        $isVerify = OpenSslHelper::verify($digestBinaryValue, $signatureBinaryValue, $signatureMethod, $publicKey);
//        $publicKey = $this->keyStore->getPublicKey(RsaKeyFormatEnum::PEM);
//        $resource = openssl_pkey_get_public($publicKey);
//        $isVerify = openssl_verify($digestBinaryValue, $signatureBinaryValue, $resource, $signatureMethod);
//        openssl_free_key($resource);
        return $isVerify;
    }
}
