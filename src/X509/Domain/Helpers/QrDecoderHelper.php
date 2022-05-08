<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use Illuminate\Support\Collection;
use ZnCore\Base\Legacy\Yii\Helpers\ArrayHelper;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;
use ZnCore\Base\Libs\FileSystem\Helpers\FileStorageHelper;

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
        $xml = new \Symfony\Component\Serializer\Encoder\XmlEncoder();
        $context = [
            'xml_format_output' => true,
            'xml_root_node_name' => 'data',
            'xml_encoding' => 'UTF-8',
//    'remove_empty_tags' => true,
        ];
        return $xml->decode($xmlContent, 'xml', $context);
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
            $item = $xml->decode($xmlContent, 'xml');
            $collection->add($item);
            $arr[] = $item;
        }
        ArrayHelper::multisort($arr, 'elementNumber');
        return new Collection($arr);
    }

    public static function collectionToBin(Collection $collection): string
    {
        $data = '';
        foreach ($collection as $item) {
            $bin = base64_decode($item['elementData']);
//            dd($item);
//            $len = strlen(bin2hex($bin)) / 2;
            //dump($len);
            $data .= $bin;
        }
        return $data;
    }

    public static function unZip($data)
    {
        $zipFile = tempnam(sys_get_temp_dir(), 'qrZip');
        FileStorageHelper::save($zipFile, $data);
        $zip = new \ZipArchive();
        $res = $zip->open($zipFile);
        if ($res === TRUE) {
            $xmlContent = $zip->getFromName('one');
            $zip->close();
        } else {
            throw new Exception('Zip not opened!');
        }
        unlink($zipFile);
        return $xmlContent;
    }
}
