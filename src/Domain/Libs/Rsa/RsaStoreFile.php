<?php

namespace PhpBundle\Kpi\Domain\Libs\Rsa;

use PhpBundle\Crypt\Domain\Libs\Encoders\EncoderInterface;
use PhpLab\Core\Exceptions\NotFoundException;
use PhpLab\Core\Helpers\StringHelper;
use PhpLab\Core\Legacy\Yii\Helpers\FileHelper;

class RsaStoreFile extends BaseRsaStore implements RsaStoreInterface
{

    private $dir;

    public function __construct(string $dir)
    {
        $this->dir = $dir;
    }

    public function getDir() {
        return $this->dir;
    }

    protected function getContent(string $name): string {
        $fileName = $this->dir . '/' . $name;
        if( ! file_exists($fileName)) {
            throw new NotFoundException("Not found $name!");
        }
        $content = FileHelper::load($fileName);
        return $content;
    }

    protected function setContent(string $name, string $content) {
        if($this->readOnly) {
            throw new \Exception('Read only!');
        }
        return FileHelper::save($this->dir . '/' . $name, $content);
    }

}
