<?php

namespace ZnCrypt\Pki\Tests\Unit;

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

    public function testHex() {
        $name = 'arrays';
        $input = file_get_contents(__DIR__ . '/../data/input/' . $name . '.json');
        $expected = "5b 35 36 2c 7b 22 64 22 3a 74 72 75 65 2c 22 31 30 22 3a 6e 75 6c 6c 2c 22 31 22 3a 5b 5d 7d 5d\n";

        $data = json_decode($input, JSON_OBJECT_AS_ARRAY | JSON_FORCE_OBJECT);
        $c14n = new C14n('hex-block');
        $actual = $c14n->encode($data);
        $decoded = $c14n->decode($actual);
        
//        dd($decoded);
        
        $this->assertSame($decoded, $data);
        $this->assertSame($expected, $actual);
    }

    /*public function testSort() {
        $name = 'arrays';
        $input = file_get_contents(__DIR__ . '/../data/input/' . $name . '.json');
        $expected = "5b 35 36 2c 7b 22 64 22 3a 74 72 75 65 2c 22 31 30 22 3a 6e 75 6c 6c 2c 22 31 22 3a 5b 5d 7d 5d\n";

        $data = json_decode($input, JSON_OBJECT_AS_ARRAY | JSON_FORCE_OBJECT);
        $c14n = new C14n('sort-locale-string');
        $actual = $c14n->encode($data);
        $decoded = $c14n->decode($actual);

        dd($actual);

        $this->assertSame($decoded, $data);
        $this->assertSame($expected, $actual);
    }*/

    private function go($name) {
        $input = file_get_contents(__DIR__ . '/../data/input/' . $name . '.json');
        $expectedJson = file_get_contents(__DIR__ . '/../data/output/' . $name . '.json');
        $expected = file_get_contents(__DIR__ . '/../data/outhex/' . $name . '.txt');

        $data = json_decode($input, JSON_OBJECT_AS_ARRAY | JSON_FORCE_OBJECT);
        $c14n = new C14n('sort-locale-string,hex-block');
        //$c14n->sort($data);
        $actual = $c14n->encode($data);
        $decoded = $c14n->decode($actual);

        //dd($decoded);

//        $this->assertSame($decoded, $data);
//        $this->assertSame($expectedJson, json_encode($data, JSON_UNESCAPED_UNICODE));
        $this->assertSame($expected, $actual);
    }
}
