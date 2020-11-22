<?php

namespace ZnCrypt\Pki\X509\Domain\Helpers;

use phpseclib\File\X509;
use SimpleXMLElement;

function XML2Array(SimpleXMLElement $parent)
{
    $array = [];
    foreach ($parent as $name => $element) {
        ($node = &$array[$name])
        && (1 === count($node) ? $node = array($node) : 1)
        && $node = &$node[];
        $node = $element->count() ? XML2Array($element) : trim($element);
    }
    return $array;
}

class XmlHelper
{

    public static function parseXml(string $ss, string $nameSpace = ''): array
    {
//        dd($ss);
        $xml = simplexml_load_string($ss, "SimpleXMLElement", 0, $nameSpace);
        $array = XML2Array($xml);
//        dd($array);
        $array = array($xml->getName() => $array);
        return $array;
    }
}
