<?php


use Illuminate\Container\Container;
use Symfony\Component\Console\Application;
use ZnCore\Base\Console\Helpers\CommandHelper;
use ZnCrypt\Pki\Domain\Libs\Rsa\RsaStoreFile;
use ZnCore\Base\Enums\Measure\TimeEnum;
use Symfony\Component\Cache\Adapter\AbstractAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Component\HttpFoundation\Request;
use ZnLib\Rest\Helpers\RestApiControllerHelper;
use ZnCore\Base\Legacy\Yii\Helpers\FileHelper;

/**
 * @var Application $application
 * @var Container $container
 */

$container = Container::getInstance();

// --- Application ---

$container->bind(Application::class, Application::class, true);

// --- Generator ---

$container->bind(RsaStoreFile::class, function () {
    $rsaDirectory = FileHelper::rootPath() . '/' . $_ENV['RSA_CA_DIRECTORY'];
    return new RsaStoreFile($rsaDirectory);
}, true);
$container->bind(AbstractAdapter::class, function () {
    $cacheDirectory = FileHelper::rootPath() . '/' . $_ENV['CACHE_DIRECTORY'];
    return new FilesystemAdapter('cryptoSession', TimeEnum::SECOND_PER_DAY, $cacheDirectory);
}, true);

CommandHelper::registerFromNamespaceList([
    'ZnCrypt\Pki\Symfony\Commands',
], $container);
