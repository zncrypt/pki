<?php

namespace PhpBundle\Kpi\Domain\Enums;

use PhpLab\Core\Domain\Base\BaseEnum;

class RsaKeyFormatEnum extends BaseEnum
{

    const TEXT = 'RSA_FORMAT_TEXT';
    const BIN = 'RSA_FORMAT_BIN';
    const PEM = 'RSA_FORMAT_PEM';

}
