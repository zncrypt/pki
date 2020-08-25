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
use PhpBundle\Kpi\Domain\Services\RsaService;
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
