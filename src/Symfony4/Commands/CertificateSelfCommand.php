<?php

namespace ZnCrypt\Pki\Symfony4\Commands;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use ZnCore\Base\FileSystem\Helpers\FilePathHelper;
use ZnCore\Base\Measure\Enums\TimeEnum;
use ZnCrypt\Base\Domain\Entities\CertificateInfoEntity;
use ZnCrypt\Base\Domain\Enums\HashAlgoEnum;
use ZnCrypt\Pki\Domain\Entities\CertificateSubjectEntity;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreFile;
use ZnCrypt\Pki\Domain\Services\CertificateService;

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
        $issuerStore = new RsaStoreFile(FilePathHelper::path($_ENV['RSA_CA_DIRECTORY']));
        //$subjectStore = new RsaStoreFile(FileHelper::path($_ENV['RSA_HOST_DIRECTORY']));

        $subjectEntity = new CertificateSubjectEntity;
        $subjectEntity->setType('company');
        $subjectEntity->setName('Root');
        $subjectEntity->setTrustLevel(300);
        $subjectEntity->setExpire(TimeEnum::SECOND_PER_YEAR * 10);
        $subjectEntity->setPublicKey($issuerStore->getPublicKey());

        $cert = $this->certificateService->make($issuerStore, $subjectEntity, HashAlgoEnum::SHA256);

        $isVerify = $this->certificateService->verify($cert);
        if ($isVerify) {
            $issuerStore->setCertificate($cert);
            $output->writeln('<fg=green>Success certification!</>');
        } else {
            $output->writeln('<fg=red>Error certification!</>');
        }

        return 0;
    }

}
