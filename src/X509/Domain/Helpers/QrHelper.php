<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use Illuminate\Support\Collection;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;

class QrHelper
{
    public static function extract(array $qrs): Collection
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

    public static function collectionToBin(Collection $collection): string
    {
        $data = '';
        foreach ($collection as $item) {
            $bin = base64_decode($item['elementData']);
            $data .= $bin;
        }
        return $data;
    }

    public static function unZip($xmlDir, $data)
    {
        $zipFile = $xmlDir . '/zip.zip';
        FileHelper::save($zipFile, $data);
        $zip = new \ZipArchive();
        $res = $zip->open($zipFile);
        if ($res === TRUE) {
            $zip->extractTo($xmlDir);
            $zip->close();
        } else {
            throw new Exception('Zip not opened!');
        }
        $xmlContent = FileHelper::load($xmlDir . '/one');
        return $xmlContent;
    }
}
