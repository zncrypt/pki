<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

class C14nSort {

    public function run($data)
    {
        $this->sort_recursive($data, 'ksort', SORT_STRING);
        return $data;
    }

    public function sort_recursive(&$array, $func, $params = null)
    {
        if (!is_array($array)) {
            return $array;
        }
        foreach ($array as &$value) {
            if (is_array($value)) {
                $this->sort_recursive($value, $func, $params);
            }
        }
        return $func($array, $params);
    }
}
