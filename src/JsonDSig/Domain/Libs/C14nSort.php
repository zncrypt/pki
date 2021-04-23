<?php

namespace ZnCrypt\Pki\JsonDSig\Domain\Libs;

class C14nSort {

    private $param;
    
    public function __construct($params)
    {
        $assoc = [
            'sort-string' => SORT_STRING, // строковое сравнение элементов
            'sort-regular' => SORT_REGULAR, // обычное сравнение элементов; подробности описаны в разделе операторы сравнения
            'sort-numeric' => SORT_NUMERIC, // числовое сравнение элементов
            'sort-locale-string' => SORT_LOCALE_STRING, // сравнение элементов как строки на основе текущего языкового стандарта. Используется языковой стандарт, который можно изменить с помощью setlocale()
            'sort-natural' => SORT_NATURAL, // сравнение элементов как строки, используя "естественный порядок", например natsort()
            'sort-flag-case' => SORT_FLAG_CASE, // можно объединять (побитовое ИЛИ) с SORT_STRING или SORT_NATURAL для сортировки строк без учёта регистра 
        ];
        $this->param = $assoc[$params];
    }

    public function run($data)
    {
        $this->sort_recursive($data, 'ksort', $this->param);
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
