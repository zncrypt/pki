<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\OpenSsl;

use ZnCrypt\Pki\Domain\Enums\RsaKeyFormatEnum;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;

class OpenSsl
{

    private $keyStore;

    public function __construct(RsaStoreInterface $keyStore)
    {
        $this->keyStore = $keyStore;
    }

    public function sign(string $data, int $signatureMethod): string
    {
        $resource = openssl_pkey_get_private($this->keyStore->getPrivateKey(), $this->keyStore->getPrivateKeyPassword());
        openssl_sign($data, $signatureBinaryValue, $resource, $signatureMethod);
        openssl_free_key($resource);
        return $signatureBinaryValue;
    }

    public function signWithPrivateKey(string $data, int $signatureMethod, $privateKey, $privateKeyPassword): string
    {
        $resource = openssl_pkey_get_private($privateKey, $privateKeyPassword);
        openssl_sign($data, $signatureBinaryValue, $resource, $signatureMethod);
        openssl_free_key($resource);
        return $signatureBinaryValue;
    }

    public function verify(string $data, string $signatureBinaryValue, int $signatureMethod): bool
    {
        $publicKey = $this->keyStore->getPublicKey(RsaKeyFormatEnum::PEM);
        $resource = openssl_pkey_get_public($publicKey);
        $isVerify = openssl_verify($data, $signatureBinaryValue, $resource, $signatureMethod);
        openssl_free_key($resource);
        return $isVerify;
    }

    public function verifyWithPublicKey(string $data, string $signatureBinaryValue, int $signatureMethod, string $publicKey): bool
    {
        $resource = openssl_pkey_get_public($publicKey);
        $isVerify = openssl_verify($data, $signatureBinaryValue, $resource, $signatureMethod);
        openssl_free_key($resource);
        return $isVerify;
    }
}
