<?php

namespace ZnCrypt\Pki\Tests\Unit\XmlDSig;

use ZnCrypt\Pki\Domain\Helpers\RsaKeyLoaderHelper;
use ZnTool\Test\Base\BaseTest;
use ZnCrypt\Pki\XmlDSig\Domain\Libs\Signature;

final class SignatureTest extends BaseTest
{

    private $directory = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/user';
    private $directoryCa = __DIR__ . '/../../data/JsonDSig/rsaKeyPair/ca';

    private $sourceXmlFile = __DIR__ . '/../../data/XmlDSig/xml/example/source.xml';
    private $signedXmlFile = __DIR__ . '/../../data/XmlDSig/xml/example/signed.xml';

    public function testSign()
    {
        $keyStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directory);
        //dd($keyStore->getPublicKey());
        $keyCaStore = RsaKeyLoaderHelper::loadKeyStoreFromDirectory($this->directoryCa);

        $signature = new Signature();
        $signature->loadPrivateKey($keyStore->getPrivateKey(), $keyStore->getPrivateKeyPassword());
        $signature->loadPublicKey($keyStore->getPublicKey());

        $sourceXml = file_get_contents($this->sourceXmlFile);
        $signedXmlExpected = file_get_contents($this->signedXmlFile);

        $signedXml = $signature->sign($sourceXml);
        //file_put_contents($this->signedXmlFile, $signedXml);
        $this->assertSame($signedXmlExpected, $signedXml);

        //$signature->setRootCa($keyCaStore->getCertificate());
        //$verifyEntity = $signature->verify($signedXml);
        //dd($verifyEntity);
    }

}
