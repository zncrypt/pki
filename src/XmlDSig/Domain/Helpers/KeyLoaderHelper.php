<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Helpers;

use FG\X509\PrivateKey;
use phpseclib\Crypt\RSA;
use phpseclib\File\X509;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;
use ZnCore\Base\Libs\Entity\Helpers\EntityHelper;
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

            $private_key = openssl_pkey_get_private($results['pkey']);
            $pem_public_key = openssl_pkey_get_details($private_key);

//            openssl_pkey_export($private_key, $privateKeyPem, $password);
//            $keyEntity->setPrivateKey($privateKeyPem);
            $keyEntity->setPublicKey($pem_public_key['key']);

            return $keyEntity;
        } else {
            throw new \Exception('Bad p12');
        }
    }
/*
    public static function loadFromDirectory(string $directory): KeyEntity
    {
        $names = [
            'certificate' => 'certificate.pem',
            'certificateRequest' => 'certificateRequest.pem',
            'privateKeyPassword' => 'password.txt',
            'privateKey' => 'private.pem',
            'publicKey' => 'public.pem',
            'p12' => 'rsa.p12',
        ];

        $data = [];
        foreach ($names as $attributeName => $fileName) {
            $file = $directory . '/' . $fileName;
            if(file_exists($file)) {
                $data[$attributeName] = FileHelper::load($file);
            }
        }

        $userKeyEntity = new KeyEntity;
        EntityHelper::setAttributes($userKeyEntity, $data);
        return $userKeyEntity;
    }

    public static function saveToDirectory(string $directory, KeyEntity $keyEntity): void
    {
        $names = [
            'certificate' => 'certificate.pem',
            'certificateRequest' => 'certificateRequest.pem',
            'csr' => 'certificateRequest.pem',
            'privateKeyPassword' => 'password.txt',
            'privateKey' => 'private.pem',
            'publicKey' => 'public.pem',
            'p12' => 'rsa.p12',
        ];

        $data = EntityHelper::toArray($keyEntity);

        foreach ($data as $attributeName => $value) {
            if(!empty($value)) {
                $fileName = $names[$attributeName];
                $file = $directory . '/' . $fileName;
                //dd($file);
                FileHelper::save($file, $value);
            }
        }
    }*/
}
