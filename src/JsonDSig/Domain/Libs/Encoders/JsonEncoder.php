<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

use ZnCore\Base\Interfaces\EncoderInterface;

class JsonEncoder implements EncoderInterface
{

    private $formatArray;

    public function __construct($format)
    {
        $this->formatArray = $format;
    }

    public function encode($data)
    {
        $json = json_encode($data, JSON_UNESCAPED_UNICODE);
        return $json;
    }

    public function decode($encoded)
    {
        $data = json_decode($encoded, JSON_OBJECT_AS_ARRAY);
        return $data;
    }
}
