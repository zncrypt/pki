<?php

namespace ZnCrypt\Pki\Domain\Helpers;

use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreRam;
use ZnCrypt\Pki\XmlDSig\Domain\Entities\KeyEntity;

class RsaKeyLoaderHelper
{

    /*public static function loadKeyStoreFromDirectory111(string $dir): RsaStoreInterface
    {
        $privateKey = $dir . '/private.pem';
        $privateKeyPassword = $dir . '/password.txt';
        $publicKey = $dir . '/public.pem';
        $certificate = $dir . '/certificate.pem';

        $keyStore = new KeyEntity();
        $keyStore->setPrivateKey(file_get_contents($privateKey));
        $keyStore->setPublicKey(file_get_contents($publicKey));
        $keyStore->setCertificate(file_get_contents($certificate));
        $keyStore->setPrivateKeyPassword(file_get_contents($privateKeyPassword));
        return $keyStore;
    }*/

    public static function loadKeyStoreFromDirectory(string $dir): RsaStoreInterface
    {
        $privateKey = $dir . '/private.pem';
        $privateKeyPassword = $dir . '/password.txt';
        $publicKey = $dir . '/public.pem';
        $certificate = $dir . '/certificate.pem';

        $keyStore = new RsaStoreRam();
        $keyStore->setPrivateKey(file_get_contents($privateKey));
        $keyStore->setPublicKey(file_get_contents($publicKey));
        $keyStore->setCertificate(file_get_contents($certificate));
        $keyStore->setPrivateKeyPassword(file_get_contents($privateKeyPassword));
        return $keyStore;
    }

    public static function saveKeyStoreFromDirectory(RsaStoreInterface $keyStore, string $dir)
    {
        FileHelper::save($dir . '/certificate.pem', $keyStore->getCertificate());
        FileHelper::save($dir . '/private.pem', $keyStore->getPrivateKey());
        FileHelper::save($dir . '/public.pem', $keyStore->getPublicKey());
        FileHelper::save($dir . '/password.txt', $keyStore->getPrivateKeyPassword());
        FileHelper::save($dir . '/rsa.p12', $keyStore->getP12());
    }
}
