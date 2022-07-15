<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Libs\KeyLoaders;

use ZnCore\Code\Helpers\PropertyHelper;
use ZnCore\Collection\Interfaces\Enumerable;
use ZnCore\Collection\Libs\Collection;
use ZnCore\FileSystem\Helpers\FileHelper;
use ZnCore\FileSystem\Helpers\FileStorageHelper;
use ZnCore\FileSystem\Helpers\FindFileHelper;
use ZnCrypt\Pki\XmlDSig\Domain\Entities\KeyEntity;
use ZnDomain\Entity\Helpers\EntityHelper;

class DirectoryKeyLoader
{

    private $directory;
    private $names = [
        'certificate' => 'certificate.pem',
        'certificateRequest' => 'certificateRequest.pem',
        'csr' => 'certificateRequest.pem',
        'privateKeyPassword' => 'password.txt',
        'privateKey' => 'private.pem',
        'publicKey' => 'public.pem',
        'p12' => 'rsa.p12',
    ];

    public function __construct(string $directory = null)
    {
        $this->directory = $directory;
    }

    public function getDirectory(): string
    {
        return $this->directory;
    }

    public function setDirectory(string $directory): void
    {
        $this->directory = $directory;
    }

    public function findAll(): Enumerable
    {
        $files = FindFileHelper::scanDir($this->directory);
        $collection = new Collection();
        foreach ($files as $file) {
            $fileNmae = $this->directory . '/' . $file;
            if (is_dir($fileNmae)) {
                $keyEntity = $this->load($file);
                $collection->add($keyEntity);
            }
        }
        return $collection;
    }

    public function remove(string $name): void
    {
        $directory = $this->directory . '/' . $name;
        FileHelper::removeDirectory($directory);
        FileHelper::createDirectory($directory);
    }

    public function load(string $name): KeyEntity
    {
        $directory = $this->directory . '/' . $name;

        $data = [];
        foreach ($this->names as $attributeName => $fileName) {
            $file = $directory . '/' . $fileName;
            if (file_exists($file)) {
                $data[$attributeName] = FileStorageHelper::load($file);
            }
        }

        $userKeyEntity = new KeyEntity;
        PropertyHelper::setAttributes($userKeyEntity, $data);
        $userKeyEntity->setName($name);
        return $userKeyEntity;
    }

    public function save(string $name, KeyEntity $keyEntity): void
    {
        $directory = $this->directory . '/' . $name;
        $data = EntityHelper::toArray($keyEntity);
        unset($data['name']);
        foreach ($data as $attributeName => $value) {
            if (!empty($value)) {
                $fileName = $this->names[$attributeName];
                $file = $directory . '/' . $fileName;
                FileStorageHelper::save($file, $value);
            }
        }
    }
}
