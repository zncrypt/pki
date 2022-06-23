<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

use Illuminate\Support\Collection;
use ZnCore\Base\Libs\Format\Encoders\ChainEncoder;
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
//        $sortParam = SortEncoder::detect($this->formatArray);
        $sortParam = $this->detect(SortEncoder::paramName(), $this->formatArray);
        if ($sortParam) {
            $sort = new SortEncoder($sortParam);
            $encodersCollection->add($sort);
        }

//        $jsonParam = JsonEncoder::detect($this->formatArray);
        $jsonParam = $this->detect(JsonEncoder::paramName(), $this->formatArray);
        $encodersCollection->add(new JsonEncoder($jsonParam));

//        $hexParam = HexEncoder::detect($this->formatArray);
        $hexParam = $this->detect(HexEncoder::paramName(), $this->formatArray);
        if ($hexParam) {
            $encodersCollection->add(new HexEncoder($hexParam));
        }
        $this->encoders = new ChainEncoder($encodersCollection);
    }

    protected function detect(string $paramName, array $array): array
    {
        $params = [];
//        $paramName = static::paramName();
        foreach ($array as $item) {
            if (strpos($item, $paramName) === 0) {
                $params[] = $item;
            }
        }
        return $params;
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
