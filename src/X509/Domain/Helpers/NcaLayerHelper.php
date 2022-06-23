<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use ZnCore\Base\Libs\Arr\Helpers\ArrayHelper;
use ZnCrypt\Pki\X509\Domain\Entities\PersonEntity;
use ZnCrypt\Pki\X509\Domain\Entities\SignatureEntity;

class NcaLayerHelper
{

    public static function parseXmlSignature(string $xml): SignatureEntity
    {
        $xml = str_replace(['<ds:', '</ds:', ':ds='], ['<', '</', '='], $xml);
        $array = XmlHelper::parseXml($xml);
        //dd($array);
        $signatureEntity = new SignatureEntity();
        $signatureEntity->setDigest($array['root']['Signature']['SignedInfo']['Reference']['DigestValue']);
        $signatureEntity->setSignature($array['root']['Signature']['SignatureValue']);
        $signatureEntity->setCertificate($array['root']['Signature']['KeyInfo']['X509Data']['X509Certificate']);
        return $signatureEntity;
    }
}
