<?php

namespace ZnCrypt\Pki\Domain\Helpers;

use ZnCore\Base\Libs\FileSystem\Helpers\FileStorageHelper;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreRam;

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
        FileStorageHelper::save($dir . '/certificate.pem', $keyStore->getCertificate());
        FileStorageHelper::save($dir . '/private.pem', $keyStore->getPrivateKey());
        FileStorageHelper::save($dir . '/public.pem', $keyStore->getPublicKey());
        FileStorageHelper::save($dir . '/password.txt', $keyStore->getPrivateKeyPassword());
        FileStorageHelper::save($dir . '/rsa.p12', $keyStore->getP12());
    }
}
