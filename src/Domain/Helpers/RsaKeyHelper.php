<?php

namespace ZnCrypt\Pki\Domain\Helpers;

use ZnCrypt\Pki\Domain\Entities\CertificateSubjectEntity;
use ZnCore\Domain\Helpers\EntityHelper;
use ZnCore\Base\Libs\Text\Helpers\StringHelper;

class RsaKeyHelper
{

    public static function keyToLine($key) {
//        $key = trim($key);
        $key = preg_replace('/-----([^-]+)-----/i', '', $key);
        $key = preg_replace('/\s+/i', '', $key);
        return $key;
    }

    public static function pemToBin($key) {
        $key = self::keyToLine($key);
        $key = base64_decode($key);
        return $key;
    }

    public static function binToPem($key, $tag) {
        $key = base64_encode($key);
        $key = self::base64ToPem($key, $tag);
        return $key;
    }

    public static function base64ToPem($key, $tag) {
        //$key = chunk_split($key);
        $key = self::keyToLine($key);
        $key = wordwrap($key, 64, PHP_EOL, true);
        $tag = mb_strtoupper($tag);
        $key = "-----BEGIN $tag-----\n$key\n-----END $tag-----";
        return $key;
    }

    public static function subjectArrayToJson(array $subjectArray): string
    {
        $subjectArray['publicKey'] = self::keyToLine($subjectArray['publicKey']);
        ksort($subjectArray);

        $arr = [];
        foreach ($subjectArray as $key => $value) {
            $arr[] = $key . ':' . $value;
        }
        $subjectJson = implode('|', $arr);

        //$subjectJson = json_encode($subjectArray);

        return $subjectJson;
    }

}
