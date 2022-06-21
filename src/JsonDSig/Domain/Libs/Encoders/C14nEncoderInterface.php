<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

use ZnCore\Contract\Encoder\Interfaces\EncoderInterface;

interface C14nEncoderInterface extends EncoderInterface
{

    public static function paramName(): string;

}
