<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use phpseclib\File\X509;
use SimpleXMLElement;

class XmlHelper
{
    public static function XML2Array(SimpleXMLElement $parent)
    {
        $array = [];
        foreach ($parent as $name => $element) {
            ($node = &$array[$name])
            && (1 === count($node) ? $node = array($node) : 1)
            && $node = &$node[];
            $node = $element->count() ? self::XML2Array($element) : trim($element);
        }
        return $array;
    }

    public static function parseXml(string $ss): array
    {
        $xml = simplexml_load_string($ss);
        $array = self::XML2Array($xml);
        $array = array($xml->getName() => $array);
        return $array;
    }
}
