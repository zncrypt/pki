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
use ZnCrypt\Pki\Domain\Services\RsaService;
use ZnCore\Base\Console\Question\ChoiceQuestion;
use ZnCore\Base\Domain\Helpers\EntityHelper;
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
use Symfony\Component\Console\Question\Question;

class RsaGenerateCommand extends BaseGeneratorCommand
{

    protected static $defaultName = 'crypt:rsa:generate';
    private $rsaService;

    public function __construct(string $name = null, RsaService $rsaService)
    {
        parent::__construct($name);
        $this->rsaService = $rsaService;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $rsaDir = FileHelper::path($_ENV['RSA_DIRECTORY']);

        do {
            $question = new Question('Enter project name: ');
            $helper = $this->getHelper('question');
            $profileName = $helper->ask($input, $output, $question);
            $dir = $rsaDir . DIRECTORY_SEPARATOR . $profileName;
            $isValid = true;
            if(empty($profileName)) {
                $output->writeln('<fg=yellow>Empty!</>');
                $isValid = false;
            }
            if(is_dir($dir)) {
                $output->writeln('<fg=yellow>Already exists!</>');
                $isValid = false;
            }
        } while( ! $isValid);

        $subjectStore = new RsaStoreFile($rsaDir . DIRECTORY_SEPARATOR . $profileName);
        $subjectStore->enableWrite();

        $this->rsaService->generatePair($subjectStore);
        $output->writeln('<fg=green>Success generated!</>');

        return 0;
    }

}
