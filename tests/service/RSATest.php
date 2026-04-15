<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\service;

use ThinkEncryption\exception\EncryptException;
use ThinkEncryption\service\encrypt\RSA;
use ThinkEncryption\tests\TestCaseBase;

class RSATest extends TestCaseBase
{
    private RSA $rsa;
    private bool $opensslAvailable;

    protected function setUp(): void
    {
        parent::setUp();

        // 检查 OpenSSL 是否可用
        $this->opensslAvailable = function_exists('openssl_pkey_new') &&
            openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]) !== false;

        if (!$this->opensslAvailable) {
            $this->markTestSkipped('OpenSSL is not properly configured on this system');
        }

        $this->rsa = new RSA($this->testKeyDir, 2048);
    }

    public function testGenerateKeyPair2048(): void
    {
        $keys = $this->rsa->generateKeyPair(2048);

        $this->assertArrayHasKey('private_key', $keys);
        $this->assertArrayHasKey('public_key', $keys);
        $this->assertStringStartsWith('-----BEGIN RSA PRIVATE KEY-----', $keys['private_key']);
        $this->assertStringStartsWith('-----BEGIN RSA PUBLIC KEY-----', $keys['public_key']);
    }

    public function testGenerateKeyPair3072(): void
    {
        $rsa3072 = new RSA($this->testKeyDir . '3072', 3072);
        $keys = $rsa3072->generateKeyPair(3072);

        $this->assertArrayHasKey('private_key', $keys);
        $this->assertArrayHasKey('public_key', $keys);
    }

    public function testSaveAndLoadKeys(): void
    {
        $this->rsa->generateKeyPair();
        $paths = $this->rsa->saveKeys();

        $this->assertFileExists($paths['private_key_path']);
        $this->assertFileExists($paths['public_key_path']);

        // 加载密钥
        $rsa2 = new RSA($this->testKeyDir, 2048);
        $result = $rsa2->loadKeys();
        $this->assertTrue($result['private_key_loaded']);
        $this->assertTrue($result['public_key_loaded']);
    }

    public function testEncryptDecrypt(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        $originalData = 'Hello, RSA with OAEP!';
        $encrypted = $this->rsa->encrypt($originalData);
        $decrypted = $this->rsa->decrypt($encrypted);

        $this->assertEquals($originalData, $decrypted);
    }

    public function testOaepPaddingCalculation(): void
    {
        // OAEP padding 计算: (keyBits / 8) - 2 * hash_length - 2
        // SHA256 hash_length = 32
        // 2048 bits: 256 - 66 - 2 = 190
        $this->assertEquals(190, (int) floor((2048 / 8) - 2 * 32 - 2));

        // 3072 bits: 384 - 66 - 2 = 316
        $this->assertEquals(316, (int) floor((3072 / 8) - 2 * 32 - 2));
    }

    public function testSignAndVerify(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        $data = 'Data to sign';
        $signature = $this->rsa->sign($data);

        $this->assertTrue($this->rsa->verify($data, $signature));
        $this->assertFalse($this->rsa->verify($data . ' modified', $signature));
    }

    public function testGetKeyBits(): void
    {
        $this->rsa->generateKeyPair(2048);
        $this->assertEquals(2048, $this->rsa->getKeyBits());

        $rsa3072 = new RSA($this->testKeyDir . '3072', 3072);
        $rsa3072->generateKeyPair(3072);
        $this->assertEquals(3072, $rsa3072->getKeyBits());
    }

    public function testKeyExists(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        $exists = $this->rsa->keyExists();
        $this->assertTrue($exists['private_key_exists']);
        $this->assertTrue($exists['public_key_exists']);
    }
}
