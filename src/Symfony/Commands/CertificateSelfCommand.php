<?php

namespace ZnCrypt\Pki\Symfony\Commands;

use Illuminate\Container\Container;
use ZnCrypt\Pki\Domain\Entities\CertificateEntity;
use ZnCrypt\Base\Domain\Entities\CertificateInfoEntity;
use ZnCrypt\Pki\Domain\Entities\CertificateSubjectEntity;
use ZnCrypt\Base\Domain\Enums\HashAlgoEnum;
use ZnCrypt\Pki\Domain\Libs\Rsa\Rsa;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreFile;
use ZnCrypt\Pki\Domain\Services\CertificateService;
use ZnCore\Domain\Helpers\EntityHelper;
use ZnCore\Base\Enums\Measure\TimeEnum;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;
use ZnTool\Dev\Generator\Domain\Dto\BuildDto;
use ZnTool\Dev\Generator\Domain\Interfaces\Services\DomainServiceInterface;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\DomainNameInputScenario;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\DomainNamespaceInputScenario;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\DriverInputScenario;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\EntityAttributesInputScenario;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\IsCrudRepositoryInputScenario;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\IsCrudServiceInputScenario;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\NameInputScenario;
use ZnTool\Dev\Generator\Domain\Scenarios\Input\TypeInputScenario;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class CertificateSelfCommand extends BaseGeneratorCommand
{

    protected static $defaultName = 'crypt:certificate:self';
    private $certificateService;

    public function __construct(string $name = null, CertificateService $certificateService)
    {
        parent::__construct($name);
        $this->certificateService = $certificateService;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $issuerStore = new RsaStoreFile(FileHelper::path($_ENV['RSA_CA_DIRECTORY']));
        //$subjectStore = new RsaStoreFile(FileHelper::path($_ENV['RSA_HOST_DIRECTORY']));

        $subjectEntity = new CertificateSubjectEntity;
        $subjectEntity->setType('company');
        $subjectEntity->setName('Root');
        $subjectEntity->setTrustLevel(300);
        $subjectEntity->setExpire(TimeEnum::SECOND_PER_YEAR * 10);
        $subjectEntity->setPublicKey($issuerStore->getPublicKey());

        $cert = $this->certificateService->make($issuerStore, $subjectEntity, HashAlgoEnum::SHA256);

        $isVerify = $this->certificateService->verify($cert);
        if($isVerify) {
            $issuerStore->setCertificate($cert);
            $output->writeln('<fg=green>Success certification!</>');
        } else {
            $output->writeln('<fg=red>Error certification!</>');
        }

        return 0;
    }

}
