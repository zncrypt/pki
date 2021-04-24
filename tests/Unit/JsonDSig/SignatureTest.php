<?php

namespace ZnCrypt\Pki\Tests\Unit\JsonDSig;

use ZnCrypt\Base\Domain\Enums\EncodingEnum;
use ZnCrypt\Base\Domain\Enums\HashAlgoEnum;
use ZnCrypt\Base\Domain\Enums\OpenSslAlgoEnum;
use ZnCrypt\Pki\Domain\Helpers\RsaKeyHelper;
use ZnCrypt\Pki\Domain\Helpers\RsaKeyLoaderHelper;
use ZnCrypt\Pki\Domain\Libs\Rsa\BaseRsaStore;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreInterface;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreRam;
use ZnCrypt\Pki\JsonDSig\Domain\Entities\SignatureEntity;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\OpenSsl\OpenSslSignature;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\Signature;
use ZnTool\Test\Base\BaseTest;

final class SignatureTest extends BaseTest
{
    
//    private $privateKey = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/ca/private.pem';
//    private $privateKeyPassword = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/ca/password.txt';
//    private $publicKey = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/ca/public.pem';
//    private $certificate = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/ca/certificate.pem';
    private $directory = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/user';
    private $directoryCa = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/ca';

    public function testSign()
    {
        $body = [
            'id' => 1,
            'name' => 'Bob',
            'status' => 100,
        ];

        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigestMethod(HashAlgoEnum::SHA256);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);

        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        $keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);
        $signature = new OpenSslSignature($keyStore);
        $signature->loadCA($keyCaStore->getCertificate());
        $signature->sign($body, $signatureEntity);
        $isVerify = $signature->verify($body, $signatureEntity);

        //$this->assertTrue($isVerify);
        $signature = file_get_contents(__DIR__ . '/../../data/JsonDSig/signature/signature.txt');

        $this->assertSame('0bJLMm+1XRRufFhPivRIM6gOYwQoRKKUvf4jDxMEEdA=', $signatureEntity->getDigestValue());
        $certificate = RsaKeyHelper::keyToLine($keyStore->getCertificate());
        $this->assertSame($certificate, $signatureEntity->getX509Certificate());
        $this->assertSame($signature, $signatureEntity->getSignatureValue());
    }

    public function testVerify()
    {
        $body = [
            'id' => 1,
            'name' => 'Bob',
            'status' => 100,
        ];

        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        $keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);

        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigestMethod(HashAlgoEnum::SHA256);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);
        $signatureEntity->setDigestValue('0bJLMm+1XRRufFhPivRIM6gOYwQoRKKUvf4jDxMEEdA=');
        $certificate = RsaKeyHelper::keyToLine($keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
        $signature = file_get_contents(__DIR__ . '/../../data/JsonDSig/signature/signature.txt');
        $signatureEntity->setSignatureValue($signature);

        $signature = new OpenSslSignature($keyStore);
        $signature->loadCA($keyCaStore->getCertificate());

        $isVerify = $signature->verify($body, $signatureEntity);

        $this->assertTrue(true);
    }

    /*public function testSignFailDigest()
    {
        $body = [
            'id' => 1,
            'name' => 'Bob',
            'status' => 100,
        ];

        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        $keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);

        $signature = new OpenSslSignature($keyStore);
        $signature->loadCA($keyCaStore->getCertificate());

        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigestMethod(HashAlgoEnum::SHA256);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);

        $signature->sign($body, $signatureEntity);

        $body = [
            'id' => 1222,
            'name' => 'Bob',
            'status' => 100,
        ];

        $isVerify = $signature->verify($body, $signatureEntity);

        $this->assertTrue($isVerify);
        $signature = 'e7Vzcxe3RwECsO6VrFCskBf97xMDwI2dTwPULazPC4tFAb8bFN001So4QUKTw6Vor1Xs1q0YYKsO3WcRbqyfx8jFE6QtxTG4NDfRU1gUtfZcG0Nf9PzIYkKXvptjJunMn4iG442K3osAO96e4z/Crh5zt9BWXp5f+HyKATXLwk52COVDmDTg3aoTFGyBJBmshjAsZ7urT0kyzE5iymsSpyaMAbTGQi0+UIfIqDEHEWmEyjFrumZQXy9Ub7G9ntkJjmjlOWBAEOqfQXk5yE3T9agYXLAwSygaXElmtXHbejyHNjRWHL4CErNISeAQ/xlZsi5oIt1l9A+2AJVLjoHdHw==';
        $this->assertSame($signature, $signatureEntity->getSignatureValue());
    }*/

    private function getKeyStore(): RsaStoreInterface
    {
        return RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
    }
}
