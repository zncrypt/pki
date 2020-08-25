<?php

namespace PhpBundle\Kpi\Domain\Libs\Rsa;

use PhpLab\Core\Exceptions\NotFoundException;

class RsaStoreRam extends BaseRsaStore
{

    protected $data = [];

    protected function getContent(string $name): string {
        if( empty($this->data[$name])) {
            throw new NotFoundException("Not found $name!");
        }
        $content = $this->data[$name];
        return $content;
    }

    protected function setContent(string $name, string $content) {
        if($this->readOnly) {
            //throw new \Exception('Read only!');
        }
        $this->data[$name] = $content;
    }

}
