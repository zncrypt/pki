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

    public function go($name) {
        $input = file_get_contents(__DIR__ . '/../data/input/' . $name . '.json');
        $expectedJson = file_get_contents(__DIR__ . '/../data/output/' . $name . '.json');
        $expected = file_get_contents(__DIR__ . '/../data/outhex/' . $name . '.txt');

        $data = json_decode($input, JSON_OBJECT_AS_ARRAY | JSON_FORCE_OBJECT);
        $c14n = new C14n();
        //$c14n->sort($data);
        $actual = $c14n->encode($data);
        $decoded = $c14n->decode($actual);
        
        //dd($decoded);
        
//        $this->assertSame($decoded, $data);
//        $this->assertSame($expectedJson, json_encode($data, JSON_UNESCAPED_UNICODE));
        $this->assertSame($expected, $actual);
    }
}
