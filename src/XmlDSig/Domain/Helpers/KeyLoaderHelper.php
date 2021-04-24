<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Helpers;

use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;
use ZnCrypt\Pki\XmlDSig\Domain\Entities\KeyEntity;

class KeyLoaderHelper
{

    public static function loadFromP12(string $p12, string $password): KeyEntity
    {
        $worked = openssl_pkcs12_read($p12, $results, $password);
        if($worked) {
            $keyEntity = new KeyEntity();
            $keyEntity->setPrivateKey($results['pkey']);
            $keyEntity->setCertificate($results['cert']);
            $keyEntity->setP12($p12);

            $private_key = openssl_pkey_get_private($keyEntity->getPrivateKey());
            $pem_public_key = openssl_pkey_get_details($private_key);
            $keyEntity->setPublicKey($pem_public_key['key']);
            return $keyEntity;
        } else {
            throw new \Exception('Bad p12');
        }
    }
}
