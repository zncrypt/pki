<?php

namespace ZnCrypt\Pki\XmlDSig\Domain\Libs\KeyLoaders;

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

    public function remove(string $name): void
    {
        $pkiDirectory = DotEnv::get('PKI_DIRECTORY');
        $directory = $pkiDirectory . '/' . $name;
        FileHelper::removeDirectory($directory);
        //FileHelper::createDirectory('user');
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
        foreach ($data as $attributeName => $value) {
            if(!empty($value)) {
                $fileName = $this->names[$attributeName];
                $file = $directory . '/' . $fileName;
                FileHelper::save($file, $value);
            }
        }
    }

    
    
    
    
    
    public function load111(string $directory): KeyEntity
    {
        $directory = $directory ?? DotEnv::get('PKI_DIRECTORY');
        $names = [
            'certificate' => 'certificate.pem',
            'certificateRequest' => 'certificateRequest.pem',
            'privateKeyPassword' => 'password.txt',
            'privateKey' => 'private.pem',
            'publicKey' => 'public.pem',
            'p12' => 'rsa.p12',
        ];

        $data = [];
        foreach ($names as $attributeName => $fileName) {
            $file = $directory . '/' . $fileName;
            if(file_exists($file)) {
                $data[$attributeName] = FileHelper::load($file);
            }
        }

        $userKeyEntity = new KeyEntity;
        EntityHelper::setAttributes($userKeyEntity, $data);
        return $userKeyEntity;
    }

    public function save1111(string $directory, KeyEntity $keyEntity): void
    {
        $directory = $directory ?? DotEnv::get('PKI_DIRECTORY');
        $names = [
            'certificate' => 'certificate.pem',
            'certificateRequest' => 'certificateRequest.pem',
            'csr' => 'certificateRequest.pem',
            'privateKeyPassword' => 'password.txt',
            'privateKey' => 'private.pem',
            'publicKey' => 'public.pem',
            'p12' => 'rsa.p12',
        ];

        $data = EntityHelper::toArray($keyEntity);

        foreach ($data as $attributeName => $value) {
            if(!empty($value)) {
                $fileName = $names[$attributeName];
                $file = $directory . '/' . $fileName;
                //dd($file);
                FileHelper::save($file, $value);
            }
        }
    }
}
