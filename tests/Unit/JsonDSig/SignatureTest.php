<?php

namespace ZnCrypt\Pki\Tests\Unit\JsonDSig;

use ZnCrypt\Base\Domain\Enums\EncodingEnum;
use ZnCrypt\Base\Domain\Enums\HashAlgoEnum;
use ZnCrypt\Base\Domain\Enums\OpenSslAlgoEnum;
use ZnCrypt\Base\Domain\Exceptions\FailCertificateSignatureException;
use ZnCrypt\Base\Domain\Exceptions\FailSignatureException;
use ZnCrypt\Base\Domain\Exceptions\InvalidDigestException;
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
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setSignatureFormat(EncodingEnum::BASE64);

        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        $keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);
        $openSslSignature = new OpenSslSignature($keyStore);
        $openSslSignature->loadCA($keyCaStore->getCertificate());
        $openSslSignature->sign($body, $signatureEntity);
        $openSslSignature->verify($body, $signatureEntity);

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
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setSignatureFormat(EncodingEnum::BASE64);
        $signatureEntity->setDigestValue('0bJLMm+1XRRufFhPivRIM6gOYwQoRKKUvf4jDxMEEdA=');
        $certificate = RsaKeyHelper::keyToLine($keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
        $signature = file_get_contents(__DIR__ . '/../../data/JsonDSig/signature/signature.txt');
        $signatureEntity->setSignatureValue($signature);

        $openSslSignature = new OpenSslSignature($keyStore);
        $openSslSignature->loadCA($keyCaStore->getCertificate());
        $openSslSignature->verify($body, $signatureEntity);

        $this->assertTrue(true);
    }

    public function testVerifySort()
    {
        $body = [
            'status' => 100,
            'name' => 'Bob',
            'id' => 1,
        ];

        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        $keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);

        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigestMethod(HashAlgoEnum::SHA256);
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setSignatureFormat(EncodingEnum::BASE64);
        $signatureEntity->setDigestValue('0bJLMm+1XRRufFhPivRIM6gOYwQoRKKUvf4jDxMEEdA=');
        $certificate = RsaKeyHelper::keyToLine($keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
        $signature = file_get_contents(__DIR__ . '/../../data/JsonDSig/signature/signature.txt');
        $signatureEntity->setSignatureValue($signature);

        $openSslSignature = new OpenSslSignature($keyStore);
        $openSslSignature->loadCA($keyCaStore->getCertificate());
        $openSslSignature->verify($body, $signatureEntity);

        $this->assertTrue(true);
    }

    public function testVerifyBadDigest()
    {
        $body = [
            'id' => 11111111,
            'name' => 'Bob',
            'status' => 100,
        ];

        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        $keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);

        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigestMethod(HashAlgoEnum::SHA256);
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setSignatureFormat(EncodingEnum::BASE64);
        $signatureEntity->setDigestValue('0bJLMm+1XRRufFhPivRIM6gOYwQoRKKUvf4jDxMEEdA=');
        $certificate = RsaKeyHelper::keyToLine($keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
        $signature = file_get_contents(__DIR__ . '/../../data/JsonDSig/signature/signature.txt');
        $signatureEntity->setSignatureValue($signature);

        $openSslSignature = new OpenSslSignature($keyStore);
        $openSslSignature->loadCA($keyCaStore->getCertificate());

        $this->expectException(InvalidDigestException::class);
        $openSslSignature->verify($body, $signatureEntity);
    }

    public function testVerifyFailSignature()
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
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setSignatureFormat(EncodingEnum::BASE64);
        $signatureEntity->setDigestValue('0bJLMm+1XRRufFhPivRIM6gOYwQoRKKUvf4jDxMEEdA=');
        $certificate = RsaKeyHelper::keyToLine($keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
        $signature = file_get_contents(__DIR__ . '/../../data/JsonDSig/signature/signatureFail.txt');
        $signatureEntity->setSignatureValue($signature);

        $openSslSignature = new OpenSslSignature($keyStore);
        $openSslSignature->loadCA($keyCaStore->getCertificate());

        $this->expectException(FailSignatureException::class);
        $openSslSignature->verify($body, $signatureEntity);
    }

    public function testVerifyFailCertificateSignature()
    {
        $body = [
            'id' => 1,
            'name' => 'Bob',
            'status' => 100,
        ];

        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        //$keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);

        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigestMethod(HashAlgoEnum::SHA256);
        $signatureEntity->setDigestFormat(EncodingEnum::BASE64);
        $signatureEntity->setSignatureMethod(OpenSslAlgoEnum::SHA256);
        $signatureEntity->setSignatureFormat(EncodingEnum::BASE64);
        $signatureEntity->setDigestValue('0bJLMm+1XRRufFhPivRIM6gOYwQoRKKUvf4jDxMEEdA=');
        $certificate = RsaKeyHelper::keyToLine($keyStore->getCertificate());
        $signatureEntity->setX509Certificate($certificate);
        $signature = file_get_contents(__DIR__ . '/../../data/JsonDSig/signature/signature.txt');
        $signatureEntity->setSignatureValue($signature);

        $openSslSignature = new OpenSslSignature($keyStore);
        $openSslSignature->loadCA(__DIR__ . '/../../data/JsonDSig/rsaKeyPair/caUnknown/certificate.pem');

        $this->expectException(FailCertificateSignatureException::class);
        $openSslSignature->verify($body, $signatureEntity);
    }
}
