<?php

namespace ZnCrypt\Pki\Tests\Unit\JsonDSig;

use ZnCrypt\Base\Domain\Enums\HashAlgoEnum;
use ZnCrypt\Base\Domain\Enums\OpenSslAlgoEnum;
use ZnCrypt\Pki\Domain\Libs\Rsa\BaseRsaStore;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreRam;
use ZnCrypt\Pki\JsonDSig\Domain\Entities\SignatureEntity;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\OpenSslSignature;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\Signature;
use ZnTool\Test\Base\BaseTest;

final class SignatureTest extends BaseTest
{
    
    private $privateKey = __DIR__ . '/../../data/rsaKeyPair/private.pem';
    private $privateKeyPassword = __DIR__ . '/../../data/rsaKeyPair/password.txt';
    private $publicKey = __DIR__ . '/../../data/rsaKeyPair/public.pem';
    private $certificate = __DIR__ . '/../../data/rsaKeyPair/certificate.pem';

    public function testSign()
    {
        $body = [
            'id' => 1,
            'name' => 'Bob',
            'status' => 100,
        ];

        $keyStore = $this->getKeyStore();
        $signature = new OpenSslSignature($keyStore);

        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigestMethod(HashAlgoEnum::SHA256);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);

        $signature->sign($body, $signatureEntity);

        $isVerify = $signature->verify($body, $signatureEntity);

        $this->assertTrue($isVerify);
        $signature = 'e7Vzcxe3RwECsO6VrFCskBf97xMDwI2dTwPULazPC4tFAb8bFN001So4QUKTw6Vor1Xs1q0YYKsO3WcRbqyfx8jFE6QtxTG4NDfRU1gUtfZcG0Nf9PzIYkKXvptjJunMn4iG442K3osAO96e4z/Crh5zt9BWXp5f+HyKATXLwk52COVDmDTg3aoTFGyBJBmshjAsZ7urT0kyzE5iymsSpyaMAbTGQi0+UIfIqDEHEWmEyjFrumZQXy9Ub7G9ntkJjmjlOWBAEOqfQXk5yE3T9agYXLAwSygaXElmtXHbejyHNjRWHL4CErNISeAQ/xlZsi5oIt1l9A+2AJVLjoHdHw==';
        $this->assertSame($signature, $signatureEntity->getSignatureValue());
    }

    private function getKeyStore(): BaseRsaStore
    {
        $keyStore = new RsaStoreRam();
        $keyStore->setPrivateKey(file_get_contents($this->privateKey));
        $keyStore->setPublicKey(file_get_contents($this->publicKey));
        $keyStore->setCertificate(file_get_contents($this->certificate));
        $keyStore->setPrivateKeyPassword(file_get_contents($this->privateKeyPassword));
        return $keyStore;
    }
}
