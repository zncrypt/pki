<?php

namespace ZnCrypt\Pki\X509\Domain;

use ZnCore\Domain\Domain\Interfaces\DomainInterface;

class Domain implements DomainInterface
{

    public function getName()
    {
        return 'apache';
    }

}
