<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Helpers;

class OpenSslHelper
{

    public static function sign(string $digestBinaryValue, int $signatureMethod, $privateKey, $privateKeyPassword): string
    {
        $resource = openssl_pkey_get_private($privateKey, $privateKeyPassword);
        openssl_sign($digestBinaryValue, $signatureBinaryValue, $resource, $signatureMethod);
        openssl_free_key($resource);
        return $signatureBinaryValue;
    }

    public static function verify(string $digestBinaryValue, string $signatureBinaryValue, int $signatureMethod, string $publicKey): bool
    {
        $resource = openssl_pkey_get_public($publicKey);
        $isVerify = openssl_verify($digestBinaryValue, $signatureBinaryValue, $resource, $signatureMethod);
        openssl_free_key($resource);
        return $isVerify;
    }
}
