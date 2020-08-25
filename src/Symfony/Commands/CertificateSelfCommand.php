<?php

namespace PhpBundle\Kpi\Symfony\Commands;

use Illuminate\Container\Container;
use PhpBundle\Kpi\Domain\Entities\CertificateEntity;
use PhpBundle\Crypt\Domain\Entities\CertificateInfoEntity;
use PhpBundle\Kpi\Domain\Entities\CertificateSubjectEntity;
use PhpBundle\Crypt\Domain\Enums\HashAlgoEnum;
use PhpBundle\Kpi\Domain\Libs\Rsa\Rsa;
use PhpBundle\Kpi\Domain\Libs\Rsa\RsaStoreFile;
use PhpBundle\Kpi\Domain\Services\CertificateService;
use PhpLab\Core\Domain\Helpers\EntityHelper;
use PhpLab\Core\Enums\Measure\TimeEnum;
use PhpLab\Core\Legacy\Yii\Helpers\FileHelper;
use PhpLab\Dev\Generator\Domain\Dto\BuildDto;
use PhpLab\Dev\Generator\Domain\Interfaces\Services\DomainServiceInterface;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\DomainNameInputScenario;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\DomainNamespaceInputScenario;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\DriverInputScenario;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\EntityAttributesInputScenario;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\IsCrudRepositoryInputScenario;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\IsCrudServiceInputScenario;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\NameInputScenario;
use PhpLab\Dev\Generator\Domain\Scenarios\Input\TypeInputScenario;
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
