<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs\Encoders;

class JsonEncoder extends BaseEncoder
{

    public static function paramName(): string
    {
        return 'json-';
    }

    public function encode($data)
    {
        $options = 0;
        foreach ($this->getParams() as $param) {
            $options = $options | $this->encodeParam($param);
        }
        $json = json_encode($data, $options);
        return $json;
    }

    public function decode($encoded)
    {
        $data = json_decode($encoded, JSON_OBJECT_AS_ARRAY);
        return $data;
    }

    private function encodeParam(string $param): int
    {
        $assoc = [
            'json-hex-tag' => JSON_HEX_TAG, // All &lt; and &gt; are converted to \u003C and \u003E.
            'json-hex-amp' => JSON_HEX_AMP, // All &#38;#38;s are converted to \u0026.
            'json-hex-apos' => JSON_HEX_APOS, // All ' are converted to \u0027.
            'json-hex-quot' => JSON_HEX_QUOT, // All " are converted to \u0022.
            'json-force-object' => JSON_FORCE_OBJECT, // Outputs an object rather than an array when a non-associative array is used. Especially useful when the recipient of the output is expecting an object and the array is empty.
            'json-numeric-check' => JSON_NUMERIC_CHECK, // Encodes numeric strings as numbers.
            'json-unescaped-slashes' => JSON_UNESCAPED_SLASHES, // Don't escape /.
            'json-pretty-print' => JSON_PRETTY_PRINT, // Use whitespace in returned data to format it.
            'json-unescaped-unicode' => JSON_UNESCAPED_UNICODE, // Encode multibyte Unicode characters literally (default is to escape as \uXXXX).
        ];
        return $assoc[$param];
    }
}
