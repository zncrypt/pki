<?php

namespace ZnCrypt\Pki\Domain\Services;

use ZnCrypt\Pki\Domain\Entities\CertificateEntity;
use ZnCrypt\Base\Domain\Entities\CertificateInfoEntity;
use ZnCrypt\Pki\Domain\Entities\CertificateSubjectEntity;
use ZnCrypt\Pki\Domain\Entities\RsaKeyEntity;
use ZnCrypt\Pki\Domain\Entities\SignatureEntity;
use ZnCrypt\Base\Domain\Enums\HashAlgoEnum;
use ZnCrypt\Base\Domain\Interfaces\Services\PasswordServiceInterface;
use ZnCrypt\Pki\Domain\Libs\Rsa\Rsa;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreFile;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreRam;
use ZnCore\Base\Domain\Helpers\EntityHelper;
use ZnCore\Base\Legacy\Yii\Base\Security;
use ZnCore\Base\Legacy\Yii\Helpers\ArrayHelper;

class RsaService
{

    public function generatePair(RsaStoreInterface $store, $bits = 2048, string $algo = HashAlgoEnum::SHA256)
    {
        $rsa = new \phpseclib\Crypt\RSA();
        
        $rsa->setPrivateKeyFormat(\phpseclib\Crypt\RSA::PRIVATE_FORMAT_PKCS1);
        //$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);

        //define('CRYPT_RSA_EXPONENT', 65537);
        //define('CRYPT_RSA_SMALLEST_PRIME', 64); // makes it so multi-prime RSA is used
        $keys = $rsa->createKey($bits);
        
        $store->setPublicKey($keys['publickey']);
        $store->setPrivateKey($keys['privatekey']);
    }
}
