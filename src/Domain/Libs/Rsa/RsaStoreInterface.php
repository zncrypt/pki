<?php

namespace ZnCrypt\Pki\Domain\Libs\Rsa;

use ZnCrypt\Pki\Domain\Enums\CertificateFormatEnum;
use ZnCrypt\Pki\Domain\Enums\RsaKeyFormatEnum;

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
