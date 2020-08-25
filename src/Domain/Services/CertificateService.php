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
use PhpBundle\Kpi\Domain\Helpers\RsaKeyHelper;
use PhpBundle\Kpi\Domain\Libs\Rsa\RsaStoreFile;
use PhpBundle\Kpi\Domain\Libs\Rsa\RsaStoreRam;
use PhpLab\Core\Domain\Helpers\EntityHelper;
use PhpLab\Core\Legacy\Yii\Base\Security;
use PhpLab\Core\Legacy\Yii\Helpers\ArrayHelper;

class CertificateService
{

    public function make(RsaStoreFile $issuerStore, CertificateSubjectEntity $subjectEntity, string $algo = HashAlgoEnum::SHA256): RsaKeyEntity
    {
        $subjectArray = EntityHelper::toArray($subjectEntity);
        $subjectJson = RsaKeyHelper::subjectArrayToJson($subjectArray);
        //dd($subjectJson);
        $rsa = new Rsa($issuerStore);
        $signatureEntity = $rsa->sign($subjectJson, $algo);
        $arr = [
            'subject' => $subjectArray,
            'signature' => [
                'signature' => $signatureEntity->getSignatureBase64(),
                'format' => 'base64',
                'algorithm' => 'sha256',
            ],
        ];
        //dd([$subjectEntity->getPublicKey() == $issuerStore->getPublicKey()]);
        if($subjectEntity->getPublicKey() == $issuerStore->getPublicKey()) {
            $arr['issuer'] = 'self';
        } else {
            $issuerCert = $issuerStore->getCertificate();
            //
            $issuerCertJson = RsaKeyHelper::pemToBin($issuerCert);
            $issuerCert = json_decode($issuerCertJson);
            //dd($issuerCert);
            $arr['issuer'] = $issuerCert;
            //dd($issuerCert);
        }
        //dd($arr);

        $json = json_encode($arr, JSON_PRETTY_PRINT);
        $keyEntity = new RsaKeyEntity(RsaKeyEntity::CERTIFICATE, $json);
        return $keyEntity;
    }

    public function verify(RsaKeyEntity $certEntity): bool
    {
        $cert = $certEntity->getRaw();
        $certArray = json_decode($cert, true);
        //dd($certArray);
        $subjectArray = $certArray['subject'];
        $subjectJson = RsaKeyHelper::subjectArrayToJson($subjectArray);
        if($certArray['issuer'] == 'self' || $certArray['issuer'] == null) {
            $issuerPublicKey = $certArray['subject']['publicKey'];
        } else {
            $issuerPublicKey = $certArray['issuer']['subject']['publicKey'];
        }
        //dd($certArray['issuer']);
        $store = new RsaStoreRam();

        $store->setPublicKey($issuerPublicKey);
        $rsa = new Rsa($store);

        $signatureEntity = new SignatureEntity;
        $signatureEntity->setSignatureBase64($certArray['signature']['signature']);
        $signatureEntity->setAlgorithm($certArray['signature']['algorithm']);
        $isVerify = $rsa->verify($subjectJson, $signatureEntity);
        //dd($subjectJson);
        if($isVerify) {
            $diff = intval($certArray['subject']['expireAt']) - time();
            if($diff < 1) {
                return false;
            }
        }
        return $isVerify;
    }
}
