<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

use Illuminate\Support\Collection;
use ZnCore\Base\Encoders\AggregateEncoder;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders\HexEncoder;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders\JsonEncoder;
use ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders\SortEncoder;

class C14n
{

    private $formatArray;
    private $encoders;

    public function __construct($format)
    {
        $this->formatArray = $format;
        $encodersCollection = new Collection();
        $sortParam = SortEncoder::detect($this->formatArray);
        if ($sortParam) {
            $sort = new SortEncoder($sortParam);
            $encodersCollection->add($sort);
        }
        $encodersCollection->add(new JsonEncoder($this->formatArray));
        $hexParam = HexEncoder::detect($this->formatArray);
        if ($hexParam) {
            $encodersCollection->add(new HexEncoder($hexParam));
        }
        $this->encoders = new AggregateEncoder($encodersCollection);
    }

    public function decode($encoded)
    {
        $data = $this->encoders->decode($encoded);
        return $data;
    }

    public function encode($data)
    {
        $data = $this->encoders->encode($data);
        return $data;
    }
}
