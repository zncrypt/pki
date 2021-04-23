<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

use ZnCore\Base\Helpers\StringHelper;
use ZnCore\Base\Interfaces\EncoderInterface;

class HexEncoder implements C14nEncoderInterface
{

    private $formatArray;

    public function __construct($format)
    {
        $this->formatArray = $format;
    }

    public static function params(): array
    {
        return ['hex-block'];
    }

    public function encode($data)
    {
        if (in_array('hex-block', $this->formatArray)) {
            $hex = $this->toHex($data, 'hex-block');
            return $hex;
        }
        return $data;
    }

    public function decode($encoded)
    {
        $hex = StringHelper::removeAllSpace($encoded);
        $json = hex2bin($hex);
        return $json;
    }

    public function toHex($json, $params)
    {
        $hex = bin2hex($json);
        $array = mb_str_split($hex, 2);
        $chunckedArray = array_chunk($array, 32);
        $string = '';
        foreach ($chunckedArray as $lineArray) {
            $string .= implode(' ', $lineArray) . "\n";
        }
        return $string;
    }
}
