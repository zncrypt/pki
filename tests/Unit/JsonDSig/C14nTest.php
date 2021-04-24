<?php

namespace ZnCrypt\Pki\Tests\Unit\JsonDSig;

use ZnCrypt\Pki\JsonDSig\Domain\Libs\C14n;
use ZnTool\Test\Base\BaseTest;

final class C14nTest extends BaseTest {
    
    public function testArray() {
        $list = [
            'arrays',
            'french',
            'unicode',
            
//            'structures',
//            'values',
//            'weird',
        ];
        foreach ($list as $name) {
            $this->go($name);
        }
    }

    public function testFrenchHexBlock() {
        $name = 'french';
        $input = file_get_contents(__DIR__ . '/../../data/JsonDSig/input/french.json');
        $expected = file_get_contents(__DIR__ . '/../../data/JsonDSig/outhex/frenchHexString.txt');

        $data = json_decode($input, JSON_OBJECT_AS_ARRAY | JSON_FORCE_OBJECT);
        $c14n = new C14n(['sort-string', 'hex-string', 'json-unescaped-unicode']);
        $actual = $c14n->encode($data);
        $decoded = $c14n->decode($actual);

        $this->assertSame($decoded, $data);
        $this->assertSame($expected, $actual);
    }

    public function testSort() {
        $name = 'arrays';
        $input = file_get_contents(__DIR__ . '/../../data/JsonDSig/input/' . $name . '.json');
        $expected = '[56,{"1":[],"10":null,"d":true}]';

        $data = json_decode($input, JSON_OBJECT_AS_ARRAY | JSON_FORCE_OBJECT);
        $c14n = new C14n(['sort-locale-string', 'json-unescaped-unicode']);
        $actual = $c14n->encode($data);
        $decoded = $c14n->decode($actual);

        $this->assertNotSame($decoded, $data);
        $this->assertSame($expected, $actual);
    }

    private function go($name) {
        $input = file_get_contents(__DIR__ . '/../../data/JsonDSig/input/' . $name . '.json');
        //$expectedJson = file_get_contents(__DIR__ . '/../../data/JsonDSig/output/' . $name . '.json');
        $expected = file_get_contents(__DIR__ . '/../../data/JsonDSig/outhex/' . $name . '.txt');

        $data = json_decode($input, JSON_OBJECT_AS_ARRAY | JSON_FORCE_OBJECT);
        $c14n = new C14n(['sort-locale-string', 'hex-block', 'json-unescaped-unicode']);
        $actual = $c14n->encode($data);
        $decoded = $c14n->decode($actual);

//        $this->assertSame($decoded, $data);
//        $this->assertSame($expectedJson, json_encode($data, JSON_UNESCAPED_UNICODE));
        $this->assertSame($expected, $actual);
    }
}
