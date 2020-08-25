<?php

namespace PhpBundle\Kpi\Domain\Helpers;

use php7rails\app\domain\helpers\EnvService;
use PhpBundle\Jwt\Domain\Entities\KeyEntity;
use PhpBundle\Crypt\Domain\Enums\EncryptAlgorithmEnum;
use PhpBundle\Crypt\Domain\Enums\RsaBitsEnum;

class RsaHelper
{

    public static function generate(string $password = null, int $keyBits = RsaBitsEnum::BIT_2048, int $keyType = OPENSSL_KEYTYPE_RSA, $algorithm = EncryptAlgorithmEnum::SHA256): KeyEntity
    {
        $config = [
            "digest_alg" => $algorithm,
            "private_key_bits" => $keyBits,
            "private_key_type" => $keyType,
        ];
        $resource = openssl_pkey_new($config);
        $keyEntity = new KeyEntity;
        $keyEntity->private = self::extractPrivateKey($resource, $password);
        $keyEntity->public = self::extractPublicKey($resource);
        return $keyEntity;
    }

    public static function extractPrivateKey($resource, string $password = null): string
    {
        openssl_pkey_export($resource, $privateKey, $password);
        return $privateKey;
    }

    public static function extractPublicKey($resource): string
    {
        $publicKey = openssl_pkey_get_details($resource);
        $publicKey = $publicKey["key"];
        return $publicKey;
    }

}
