<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

use ZnCore\Base\Interfaces\EncoderInterface;

interface C14nEncoderInterface extends EncoderInterface
{

    public static function params(): array;
}
