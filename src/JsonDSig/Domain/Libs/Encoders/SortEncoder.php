<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

use ZnCore\Base\Interfaces\EncoderInterface;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\C14nSort;

class SortEncoder implements EncoderInterface
{

    private $formatArray;

    public function __construct($format)
    {
        $this->formatArray = $format;
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
        return $data;
    }

    public function decode($encodedData)
    {
        return $encodedData;
    }

    public function sort(&$data, $params)
    {
        $sort = new C14nSort($params);
        $data = $sort->run($data);
    }
}
