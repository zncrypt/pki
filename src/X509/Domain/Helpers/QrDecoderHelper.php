<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use Illuminate\Support\Collection;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;

class QrDecoderHelper
{

    public static function extractData(array $qrs, string $nameSpace = '')
    {
        $collection = self::extract($qrs);
        $data = self::collectionToBin($collection);
        $xmlContent = self::unZip($data);
//        dd($xmlContent);
        $xml = new \Symfony\Component\Serializer\Encoder\XmlEncoder();
        return $xml->decode($xmlContent, 'xml');
//        dd($ssss);
//        $xmlArray = \ZnCrypt\Pki\X509\Domain\Helpers\XmlHelper::parseXml($xmlContent, $nameSpace);
//        $xmlArray = $xmlArray['data'];
//        return $xmlArray;
    }

    private static function extract(array $qrs): Collection
    {
        $collection = new Collection();
        foreach ($qrs as $xmlContent) {
            $item = XmlHelper::parseXml($xmlContent);
            $collection->add($item['BarcodeElement']);
        }
        $collection = $collection->sortBy(function ($value, $key) {
            return $value['elementNumber'];
        });
        return $collection;
    }

    private static function collectionToBin(Collection $collection): string
    {
        $data = '';
        foreach ($collection as $item) {
            $bin = base64_decode($item['elementData']);
            $data .= $bin;
        }
        return $data;
    }

    private static function unZip($data)
    {
<<<<<<< HEAD:src/X509/Domain/Helpers/QrDecoderHelper.php
        $zipFile = tempnam(sys_get_temp_dir(), 'qrZip');
=======
        FileHelper::createDirectory($xmlDir);
        $zipFile = $xmlDir . '/zip.zip';
>>>>>>> 8128b985a9e767c74090b129d6bd41a3364c3f88:src/X509/Domain/Helpers/QrHelper.php
        FileHelper::save($zipFile, $data);
        $zip = new \ZipArchive();
        $res = $zip->open($zipFile);
        if ($res === TRUE) {
            $xmlContent = $zip->getFromName('one');
            $zip->close();
        } else {
            throw new Exception('Zip not opened!');
        }
<<<<<<< HEAD:src/X509/Domain/Helpers/QrDecoderHelper.php
=======
        $xmlContent = FileHelper::load($xmlDir . '/one');
        unlink($zipFile);
        unlink($xmlDir . '/one');
>>>>>>> 8128b985a9e767c74090b129d6bd41a3364c3f88:src/X509/Domain/Helpers/QrHelper.php
        return $xmlContent;
    }
}
