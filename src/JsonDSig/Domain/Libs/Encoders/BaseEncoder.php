<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

abstract class BaseEncoder implements C14nEncoderInterface
{

    private $params;

    public function __construct(array $params)
    {
        $this->params = $params;
    }

    abstract public static function paramName(): string;

    protected function hasParam(string $name): bool
    {
        return in_array($name, $this->params);
    }

    protected function getParams(): array
    {
        return $this->params;
    }

    protected function getFirstParam(): string
    {
        return $this->params[0];
    }
    
    public static function detect(array $array): array
    {
        $params = [];
        $paramName = static::paramName();
        foreach ($array as $item) {
            if (strpos($item, $paramName) === 0) {
                $params[] = $item;
            }
        }
        return $params;
    }
}
