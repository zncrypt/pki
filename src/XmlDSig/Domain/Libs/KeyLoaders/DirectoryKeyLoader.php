<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Libs\KeyLoaders;

use Illuminate\Support\Collection;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;
use ZnCore\Base\Libs\DotEnv\DotEnv;
use ZnCore\Domain\Helpers\EntityHelper;
use ZnCrypt\Pki\XmlDSig\Domain\Entities\KeyEntity;

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

    public function all(): Collection
    {
        $pkiDirectory = DotEnv::get('PKI_DIRECTORY');
        $files = FileHelper::scanDir($pkiDirectory);
        $collection = new Collection();
        foreach ($files as $file) {
            $fileNmae = $pkiDirectory . '/' . $file;
            if(is_dir($fileNmae)) {
                $keyEntity = $this->load($file);
                $collection->add($keyEntity);
            }
        }
        return $collection;
    }
    
    public function remove(string $name): void
    {
        $pkiDirectory = DotEnv::get('PKI_DIRECTORY');
        $directory = $pkiDirectory . '/' . $name;
        FileHelper::removeDirectory($directory);
        FileHelper::createDirectory($directory);
    }

    public function load(string $name): KeyEntity
    {
        $pkiDirectory = DotEnv::get('PKI_DIRECTORY');
        $directory = $pkiDirectory . '/' . $name;

        $data = [];
        foreach ($this->names as $attributeName => $fileName) {
            $file = $directory . '/' . $fileName;
            if(file_exists($file)) {
                $data[$attributeName] = FileHelper::load($file);
            }
        }

        $userKeyEntity = new KeyEntity;
        EntityHelper::setAttributes($userKeyEntity, $data);
        $userKeyEntity->setName($name);
        return $userKeyEntity;
    }
    
    public function save(string $name, KeyEntity $keyEntity): void
    {
        $pkiDirectory = DotEnv::get('PKI_DIRECTORY');
        $directory = $pkiDirectory . '/' . $name;
        $data = EntityHelper::toArray($keyEntity);
        unset($data['name']);
        foreach ($data as $attributeName => $value) {
            if(!empty($value)) {
                $fileName = $this->names[$attributeName];
                $file = $directory . '/' . $fileName;
                FileHelper::save($file, $value);
            }
        }
    }
}
