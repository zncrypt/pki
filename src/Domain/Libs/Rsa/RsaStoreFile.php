<?php

namespace ZnCrypt\Pki\Domain\Libs\Rsa;

use ZnCore\Base\Libs\FileSystem\Helpers\FileStorageHelper;
use ZnCrypt\Base\Domain\Libs\Encoders\EncoderInterface;
use ZnCore\Base\Exceptions\NotFoundException;
use ZnCore\Base\Libs\Text\Helpers\StringHelper;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;

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
        $content = FileStorageHelper::load($fileName);
        return $content;
    }

    protected function setContent(string $name, string $content) {
        if($this->readOnly) {
            throw new \Exception('Read only!');
        }
        return FileStorageHelper::save($this->dir . '/' . $name, $content);
    }

}
