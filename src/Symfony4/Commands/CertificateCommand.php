<?php

namespace ZnCrypt\Pki\Symfony4\Commands;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use ZnCore\FileSystem\Helpers\FilePathHelper;
use ZnCore\FileSystem\Helpers\FindFileHelper;
use ZnLib\Components\Time\Enums\TimeEnum;
use ZnCrypt\Base\Domain\Entities\CertificateInfoEntity;
use ZnCrypt\Base\Domain\Enums\HashAlgoEnum;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreFile;
use ZnCrypt\Pki\Domain\Services\CertificateService;
use ZnLib\Console\Symfony4\Question\ChoiceQuestion;

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
        $rsaDir = FilePathHelper::path($_ENV['RSA_DIRECTORY']);
        $profiles = FindFileHelper::scanDir($rsaDir);
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
        $rsaDir = FilePathHelper::path($_ENV['RSA_DIRECTORY']);
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
