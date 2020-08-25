<?php

namespace PhpBundle\Kpi\Domain\Libs\Rsa;

use PhpBundle\Kpi\Domain\Enums\CertificateFormatEnum;
use PhpBundle\Kpi\Domain\Enums\RsaKeyFormatEnum;

interface RsaStoreInterface
{

    public function enableWrite();

    public function setCertificate(string $cert);

    public function setPublicKey(string $cert);

    public function setPrivateKey(string $cert);

    public function getCertificate(string $format = CertificateFormatEnum::JSON);

    public function getPublicKey(string $format = RsaKeyFormatEnum::TEXT);

    public function getPrivateKey(string $format = RsaKeyFormatEnum::TEXT);

}
