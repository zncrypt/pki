<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Helpers;

use App\Modules\Crypt\Domain\Entities\KeyEntity;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;

class KeyLoaderHelper
{

    public static function loadFromP12(string $p12, string $password): KeyEntity
    {
        $worked = openssl_pkcs12_read($p12, $results, $password);
        if($worked) {
            $keyEntity = new KeyEntity();
            $keyEntity->setPrivate($results['pkey']);
            $keyEntity->setCertificate($results['cert']);
            $keyEntity->setP12($p12);

            $private_key = openssl_pkey_get_private($keyEntity->getPrivate());
            $pem_public_key = openssl_pkey_get_details($private_key);
            $keyEntity->setPublic($pem_public_key['key']);
            return $keyEntity;
        } else {
            throw new \Exception('Bad p12');
        }
    }
}
