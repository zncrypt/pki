<?php

namespace PhpBundle\Kpi\Domain\Services;

use PhpBundle\Kpi\Domain\Entities\CertificateEntity;
use PhpBundle\Crypt\Domain\Entities\CertificateInfoEntity;
use PhpBundle\Kpi\Domain\Entities\CertificateSubjectEntity;
use PhpBundle\Kpi\Domain\Entities\RsaKeyEntity;
use PhpBundle\Kpi\Domain\Entities\SignatureEntity;
use PhpBundle\Crypt\Domain\Enums\HashAlgoEnum;
use PhpBundle\Crypt\Domain\Interfaces\Services\PasswordServiceInterface;
use PhpBundle\Kpi\Domain\Libs\Rsa\Rsa;
use PhpBundle\Kpi\Domain\Libs\Rsa\RsaStoreFile;
use PhpBundle\Kpi\Domain\Libs\Rsa\RsaStoreInterface;
use PhpBundle\Kpi\Domain\Libs\Rsa\RsaStoreRam;
use PhpLab\Core\Domain\Helpers\EntityHelper;
use PhpLab\Core\Legacy\Yii\Base\Security;
use PhpLab\Core\Legacy\Yii\Helpers\ArrayHelper;

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
