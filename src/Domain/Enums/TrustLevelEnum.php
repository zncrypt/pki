<?php

namespace ZnCrypt\Pki\Domain\Enums;

use ZnCore\Base\Domain\Base\BaseEnum;

class TrustLevelEnum extends BaseEnum
{

    const DIGITAL = 100;
    const FORMAL = 200;
    const PERSONAL = 300;
    const ISSUER = 400;
    const ROOT = 1000;

}
