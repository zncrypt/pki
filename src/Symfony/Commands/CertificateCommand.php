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
use PhpLab\Core\Console\Question\ChoiceQuestion;
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

class CertificateCommand extends BaseGeneratorCommand
{

    protected static $defaultName = 'crypt:certificate';
    private $certificateService;

    public function __construct(string $name = null, CertificateService $certificateService)
    {
        parent::__construct($name);
        $this->certificateService = $certificateService;
    }

    private function selectProfile($message, InputInterface $input, OutputInterface $output)
    {
        $rsaDir = FileHelper::path($_ENV['RSA_DIRECTORY']);
        $profiles = FileHelper::scanDir($rsaDir);
        $question = new ChoiceQuestion(
            $message,
            $profiles
        );
        $helper = $this->getHelper('question');
        $profileName = $helper->ask($input, $output, $question);
        return $profileName;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $rsaDir = FileHelper::path($_ENV['RSA_DIRECTORY']);
        /*$profiles = FileHelper::scanDir($rsaDir);
        $question = new ChoiceQuestion(
            'Select profile',
            $profiles
        );
        $helper = $this->getHelper('question');*/
        $issuerProfileName = $this->selectProfile('Select issuer', $input, $output);
        $subjectProfileName = $this->selectProfile('Select subject', $input, $output);

        //$profileName = 'symfony.tpl';
//        $profileName = 'root';

        $issuerStore = new RsaStoreFile($rsaDir . DIRECTORY_SEPARATOR . $issuerProfileName);
        $subjectStore = new RsaStoreFile($rsaDir . DIRECTORY_SEPARATOR . $subjectProfileName);
        $subjectStore->enableWrite();

        $subjectEntity = $subjectStore->getSubject();
        $subjectEntity->setExpire(TimeEnum::SECOND_PER_YEAR);
        $subjectEntity->setPublicKey($subjectStore->getPublicKey());

        $certEntity = $this->certificateService->make($issuerStore, $subjectEntity, HashAlgoEnum::SHA256);

        //dd($certEntity->getRaw());
        //dd($certEntity->getPem());

        $isVerify = $this->certificateService->verify($certEntity);
        if ($isVerify) {
            $subjectStore->setCertificate($certEntity->getPem());
            $output->writeln('<fg=green>Success certification!</>');
        } else {
            $output->writeln('<fg=red>Error certification!</>');
        }

        return 0;
    }

}
