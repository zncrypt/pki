<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

use ZnCore\Base\Helpers\StringHelper;

class C14n
{

    private $formatArray;

    public function __construct($format = 'sort-locale-string,hex-block')
    {
        $this->formatArray = explode(',', $format);
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
        if (in_array('sort-string', $this->formatArray)) {
            $this->sort($data, 'sort-string');
        }
        if (in_array('sort-string', $this->formatArray)) {
            $this->sort($data, 'sort-string');
        }
        if (in_array('sort-regular', $this->formatArray)) {
            $this->sort($data, 'sort-regular');
        }
        if (in_array('sort-numeric', $this->formatArray)) {
            $this->sort($data, 'sort-numeric');
        }
        if (in_array('sort-locale-string', $this->formatArray)) {
            $this->sort($data, 'sort-locale-string');
        }
        if (in_array('sort-natural', $this->formatArray)) {
            $this->sort($data, 'sort-natural');
        }
        if (in_array('sort-flag-case', $this->formatArray)) {
            $this->sort($data, 'sort-flag-case');
        }
        
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

    public function sort(&$data, $params)
    {
        $sort = new C14nSort($params);
        $data = $sort->run($data);
    }
}
