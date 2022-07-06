<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use phpseclib\File\X509;
use SimpleXMLElement;
use ZnCore\Arr\Helpers\ArrayHelper;
use ZnCrypt\Pki\X509\Domain\Entities\CertificateEntity;
use ZnCrypt\Pki\X509\Domain\Entities\PersonEntity;
use DateTime;

class X509Helper
{

    public static function extractPublicKey(string $certificateBase64): string {
        $pemCertificate = "-----BEGIN CERTIFICATE-----
".$certificateBase64."
-----END CERTIFICATE-----";
        $resourceCertificate = openssl_x509_read($pemCertificate);
        $pub_key = openssl_pkey_get_public($resourceCertificate);
        $keyData = openssl_pkey_get_details($pub_key);
        return $keyData['key'];
    }

    public static function certArrayToEntity(array $certArray, string $pemCert = null): CertificateEntity {
//        dd($certArray);
        $certificateEntity = new CertificateEntity();
        $certificateEntity->setVersion($certArray['tbsCertificate']['version']);
        $extensions = self::getAssocExt($certArray['tbsCertificate']['extensions']);

        if(isset($extensions['id-pe-authorityInfoAccess'])) {
            $arr = [];
            foreach ($extensions['id-pe-authorityInfoAccess'] as $item) {
                $method = $item['accessMethod'];
                $location = $item['accessLocation']['uniformResourceIdentifier'];
                $arr[$method] = $location;
            }
            $certificateEntity->setAuthorityInfo($arr);
        }



        /*$url = $arr['id-ad-caIssuers'];
        $fileName = preg_replace('/^[\w]+:\/\//', '', $url);
        dd($name);*/

        $certificateEntity->setExtensions($extensions);
        $certificateEntity->setIssuer(X509Helper::getAssoc($certArray['tbsCertificate']['issuer']['rdnSequence']));
        $certificateEntity->setSubject(X509Helper::getAssoc($certArray['tbsCertificate']['subject']['rdnSequence']));
        $certificateEntity->setPublicKey($certArray['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']);
        $certificateEntity->setSerialNumber($certArray['tbsCertificate']['serialNumber']);
        $certificateEntity->setCertificate($pemCert);
        $certificateEntity->setSignature([
            'algorithm' => $certArray['signatureAlgorithm']['algorithm'],
            'parameters' => X509Helper::cleanParams($certArray['signatureAlgorithm']['parameters']),
            'signatureBase64' => $certArray['signature'],
        ]);
        $certificateEntity->setCreatedAt(new DateTime($certArray['tbsCertificate']['validity']['notBefore']['utcTime']));
        $certificateEntity->setExpiredAt(new DateTime($certArray['tbsCertificate']['validity']['notAfter']['utcTime']));
        return $certificateEntity;
    }

    public static function getCertFromDomain(string $domain)
    {
        $stream = stream_context_create (array("ssl" => array("capture_peer_cert" => true)));
        $read = fopen("https://{$domain}", "rb", false, $stream);
        $cont = stream_context_get_params($read);
        $cert = ($cont["options"]["ssl"]["peer_certificate"]);
        $certData = openssl_x509_parse($cert);
        openssl_x509_export($cert, $certPem);
        openssl_x509_free( $cert );
        return $certPem;
//        $certArray = $this->x509->loadX509($certPem);
//        dd($this->x509->validateSignature());
    }

    public static function parsePerson(array $cert): PersonEntity
    {
        $person = self::getAssocFromCert($cert);
        $personEntity = self::createPersonEntity($person);
        return $personEntity;
    }

    public static function createPersonEntity(array $person): PersonEntity
    {
        $person['name'] = trim(str_replace($person['surname'], '', $person['commonName']));
        $person['code'] = str_replace('IIN', '', $person['serialNumber']);
        $personEntity = new PersonEntity();
        $personEntity->setName($person['name']);
        $personEntity->setSurname($person['surname']);
        $personEntity->setPatronymic($person['givenName']);
        $personEntity->setCode($person['code']);
        $personEntity->setEmail($person['emailAddress'] ?? '');
        return $personEntity;
    }

    public static function getAssocFromCert(array $cert): array
    {
        /*$person = [];
        foreach ($cert['tbsCertificate']['subject']['rdnSequence'] as $item) {
            $value = $item[0]['value'];
            $type = $item[0]['type'];
            $key = preg_replace('/^[\s\S]*-at-/', '', $type);
            $person[$key] = ArrayHelper::first($value);
        }*/
        $person = self::getAssoc($cert['tbsCertificate']['subject']['rdnSequence']);
        $person['name'] = trim(str_replace($person['surname'], '', $person['commonName']));
        $person['code'] = str_replace('IIN', '', $person['serialNumber']);
        return $person;
    }

    public static function cleanParams(array $params): array
    {
        $arr = [];
        foreach ($params as $key => $value) {
            if($key === 'null' && empty($value)) {
                unset($params[$key]);
            }
        }
        return $params;
    }

    public static function getAssoc1(array $rdnSequence): array
    {
        $arr = [];
        foreach ($rdnSequence as $item) {
            $value = $item[0]['value'];
            $type = $item[0]['type'];
            $key = preg_replace('/^[\s\S]*-at-/', '', $type);
            $item = [
                'name' => $key,
                'type' => $type,
                'value' => $value,
            ];
            $arr[] = $item;
            //$arr[$key] = ArrayHelper::first($value);
        }
        return $arr;
    }

    public static function getAssoc(array $rdnSequence): array
    {
        $arr = [];
        foreach ($rdnSequence as $item) {
            $value = $item[0]['value'];
            $type = $item[0]['type'];
            $key = preg_replace('/^[\s\S]*-at-/', '', $type);
            $arr[$key] = ArrayHelper::first($value);
        }
        return $arr;
    }

    public static function getAssocExt(array $rdnSequence): array
    {
        $arr = [];
        foreach ($rdnSequence as $item) {
            $value = $item['extnValue'];
            $type = $item['extnId'];
            $key = preg_replace('/^[\s\S]*-at-/', '', $type);
            $arr[$key] = $value;
        }
        return $arr;
    }
}
