<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

use ZnCore\Base\Helpers\StringHelper;

class C14n
{

    public function __construct()
    {

    }

    public function decode($hex)
    {
        $hex = StringHelper::removeAllSpace($hex);
        $json = hex2bin($hex);
        $data = json_decode($json, JSON_OBJECT_AS_ARRAY);
        return $data;
    }
    
    public function encode($data)
    {
        $this->sort($data);
        $json = json_encode($data, JSON_UNESCAPED_UNICODE);
        $hex = bin2hex($json);
        $array = mb_str_split($hex, 2);

        $chunckedArray = array_chunk($array, 32);
        $string = '';
        foreach ($chunckedArray as $lineArray) {
            $string .= implode(' ', $lineArray) . "\n";

        }
        return $string;
    }

    public function sort(&$data)
    {
        $sort = new C14nSort();
        $data = $sort->run($data);
    }
}
