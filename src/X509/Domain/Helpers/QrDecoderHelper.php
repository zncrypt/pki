<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use Illuminate\Support\Collection;
use ZnCore\Base\Legacy\Yii\Helpers\ArrayHelper;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;

class QrDecoderHelper
{

    public static function extractXml(array $qrs)
    {
        $collection = self::extract($qrs);
        $data = self::collectionToBin($collection);
        $xmlContent = self::unZip($data);
        return $xmlContent;
    }

    public static function extractData(array $qrs)
    {
        $xmlContent = self::extractXml($qrs);
//        dd($xmlContent);
        $xml = new \Symfony\Component\Serializer\Encoder\XmlEncoder();
        $context = [
            'xml_format_output' => true,
            'xml_root_node_name' => 'data',
//    'xml_encoding' => 'UTF-8',
//    'remove_empty_tags' => true,
        ];
        return $xml->decode($xmlContent, 'xml', $context);
//        dd($ssss);
//        $xmlArray = \ZnCrypt\Pki\X509\Domain\Helpers\XmlHelper::parseXml($xmlContent, $nameSpace);
//        $xmlArray = $xmlArray['data'];
//        return $xmlArray;
    }

    public static function extract(array $qrs): Collection
    {
        $xml = new \Symfony\Component\Serializer\Encoder\XmlEncoder;
        $context = [
            'xml_format_output' => true,
            'xml_root_node_name' => 'data',
//    'xml_encoding' => 'UTF-8',
//    'remove_empty_tags' => true,
        ];

        $collection = new Collection();
        $arer = [];
        foreach ($qrs as $xmlContent) {
//            $item = XmlHelper::parseXml($xmlContent);
            $item = $xml->decode($xmlContent, 'xml');
//            dd($item);
            $collection->add($item);
            $arr[] = $item;
        }
        ArrayHelper::multisort($arr, 'elementNumber');
        return new Collection($arr);
        /*dd($arr);
        $collection = $collection->sortBy(function ($value, $key) {
//            dd($value['elementNumber']);
            return intval($value['elementNumber']);
        });
        dd($collection);
        return $collection;*/
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

    public static function unZip($data)
    {
        $zipFile = tempnam(sys_get_temp_dir(), 'qrZip');
        //dd($zipFile);
        //FileHelper::createDirectory($xmlDir);
        //$zipFile = $xmlDir . '/zip.zip';
        FileHelper::save($zipFile, $data);
        $zip = new \ZipArchive();
        $res = $zip->open($zipFile);
//        dd($res);
        if ($res === TRUE) {
            $xmlContent = $zip->getFromName('one');
            $zip->close();
        } else {
            throw new Exception('Zip not opened!');
        }
//        $xmlContent = FileHelper::load($xmlDir . '/one');
//        dd($xmlContent);
        unlink($zipFile);
//        unlink($xmlDir . '/one');
        return $xmlContent;
    }
}
