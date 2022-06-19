<?php

namespace ZnCrypt\Pki\Domain\Libs\Rsa;

use ZnCrypt\Base\Domain\Libs\Encoders\EncoderInterface;
use ZnCore\Base\Exceptions\NotFoundException;


class RsaStoreRoot extends BaseRsaStore implements RsaStoreInterface
{

    protected $data = [
        self::PUBLIC_KEY_FILE => '-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB7f8ObzB11zkrB1SFqfqJ3
SORVc3yAeTnDi9hdcCPgMHaIVODzj+fbuqOa7WPIQHIRc/VxKy2tTCsWSSoY1eYU
4a2sDohfn6/FMmODXRFx3Dldd//b5UeK7tBZjxbXBJXZr+BJfjgOYDnLc+8WQded
k6T2PAYCGiZsIleFkpT26sVr1PM3G+/RZ1F4w16/iKCcZXJbje2GxZvmmwzAjCd7
2VtDqUxsl418S5/ci402Md6Gx5qDiQNRT85HsJba4u/F7p8FMmQyVVQf7roO+hWB
iu4FEdRJRkFX6u8fR08u1Ri2jMMusG55CXL4ahmnQJFcym3FaSRw/z4l1YXgj35p
AgMBAAE=
-----END PUBLIC KEY-----
',
        self::CERTIFICATE_FILE => '',
    ];

    protected function getContent(string $name): string {
        if( empty($this->data[$name])) {
            throw new NotFoundException("Not found $name!");
        }
        $content = $this->data[$name];
        return $content;
    }

    protected function setContent(string $name, string $content) {
        throw new \Exception('Read only!');
    }

}
