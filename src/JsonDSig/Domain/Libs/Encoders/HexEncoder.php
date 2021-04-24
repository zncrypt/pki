<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

use ZnCore\Base\Helpers\StringHelper;

class HexEncoder extends BaseEncoder
{

    public static function paramName(): string
    {
        return 'hex-';
    }

    public function encode($data)
    {
        $data = bin2hex($data);
        if ($this->hasParam('hex-block')) {
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

    private function toHex($json)
    {
        $array = mb_str_split($json, 2);
        $chunckedArray = array_chunk($array, 32);
        $string = '';
        foreach ($chunckedArray as $lineArray) {
            $string .= implode(' ', $lineArray) . "\n";
        }
        return $string;
    }
}
