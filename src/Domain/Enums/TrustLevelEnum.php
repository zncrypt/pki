<?php

namespace PhpBundle\Kpi\Domain\Enums;

use PhpLab\Core\Domain\Base\BaseEnum;

class TrustLevelEnum extends BaseEnum
{

    const DIGITAL = 100;
    const FORMAL = 200;
    const PERSONAL = 300;
    const ISSUER = 400;
    const ROOT = 1000;

}
