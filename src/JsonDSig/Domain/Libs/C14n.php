<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

use Illuminate\Support\Collection;
use ZnCore\Base\Encoders\AggregateEncoder;
use ZnCore\Base\Helpers\StringHelper;
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
        if (array_intersect(SortEncoder::params(), $this->formatArray)) {
            $sort = new SortEncoder($this->formatArray);
            $encodersCollection->add($sort);
        }
        $encodersCollection->add(new JsonEncoder($this->formatArray));
        if (array_intersect(HexEncoder::params(), $this->formatArray)) {
            $encodersCollection->add(new HexEncoder($this->formatArray));
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
