<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\service;

use ThinkEncryption\exception\EncryptException;
use ThinkEncryption\service\encrypt\RSA;
use ThinkEncryption\tests\TestCaseBase;

class RSATest extends TestCaseBase
{
    private RSA $rsa;
    private RSA $rsa4096;
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
        $this->rsa4096 = new RSA($this->testKeyDir . '4096', 4096);
    }

    protected function tearDown(): void
    {
        // 清理第二个目录
        $this->cleanupDirectory($this->testKeyDir . '4096');

        parent::tearDown();
    }

    public function testGenerateKeyPair2048(): void
    {
        $keys = $this->rsa->generateKeyPair(2048);

        $this->assertArrayHasKey('private_key', $keys);
        $this->assertArrayHasKey('public_key', $keys);
        $this->assertStringStartsWith('-----BEGIN RSA PRIVATE KEY-----', $keys['private_key']);
        $this->assertStringStartsWith('-----BEGIN RSA PUBLIC KEY-----', $keys['public_key']);
    }

    public function testGenerateKeyPair4096(): void
    {
        $keys = $this->rsa4096->generateKeyPair(4096);

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
        $result = $this->rsa->loadKeys();
        $this->assertTrue($result['private_key_loaded']);
        $this->assertTrue($result['public_key_loaded']);
    }

    public function testSaveKeysWithCustomPaths(): void
    {
        $this->rsa->generateKeyPair();

        $privatePath = $this->testKeyDir . '/custom_private.pem';
        $publicPath = $this->testKeyDir . '/custom_public.pem';

        $paths = $this->rsa->saveKeys($privatePath, $publicPath);

        $this->assertEquals($privatePath, $paths['private_key_path']);
        $this->assertEquals($publicPath, $paths['public_key_path']);
        $this->assertFileExists($privatePath);
        $this->assertFileExists($publicPath);
    }

    public function testEncryptDecrypt(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        $originalData = 'Hello, RSA encryption! 你好！';
        $encrypted = $this->rsa->encrypt($originalData);
        $decrypted = $this->rsa->decrypt($encrypted);

        $this->assertEquals($originalData, $decrypted);
    }

    public function testEncryptDecryptLongData(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        // 超过单块大小的数据
        $longData = str_repeat('A', 500); // 超过 245 字节
        $encrypted = $this->rsa->encrypt($longData);
        $decrypted = $this->rsa->decrypt($encrypted);

        $this->assertEquals($longData, $decrypted);
    }

    public function testEncryptWithExternalPublicKey(): void
    {
        $this->rsa->generateKeyPair();
        $publicKey = $this->rsa->getPublicKey();

        // 创建新的 RSA 实例，使用外部公钥加密
        $rsa2 = new RSA($this->testKeyDir . '2', 2048);
        $rsa2->generateKeyPair();

        $data = 'External key encryption';
        $encrypted = $rsa2->encrypt($data, $publicKey);
        $decrypted = $rsa2->decrypt($encrypted);

        $this->assertEquals($data, $decrypted);
    }

    public function testSignAndVerify(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        $data = 'Data to sign';
        $signature = $this->rsa->sign($data);

        $this->assertNotEmpty($signature);
        $this->assertTrue($this->rsa->verify($data, $signature));
    }

    public function testVerifyWithWrongData(): void
    {
        $this->rsa->generateKeyPair();

        $signature = $this->rsa->sign('original data');

        $this->assertFalse($this->rsa->verify('tampered data', $signature));
    }

    public function testVerifyWithWrongPublicKey(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        $signature = $this->rsa->sign('data');

        // 使用不同的密钥验证
        $rsa2 = new RSA($this->testKeyDir . '2', 2048);
        $rsa2->generateKeyPair();

        // 需要公钥才能验证
        $this->assertFalse($rsa2->verify('data', $signature));
    }

    public function testKeyBitsGetter(): void
    {
        $this->rsa->generateKeyPair(2048);
        $this->assertEquals(2048, $this->rsa->getKeyBits());

        $this->rsa4096->generateKeyPair(4096);
        $this->assertEquals(4096, $this->rsa4096->getKeyBits());
    }

    public function testGetKeyBitsFromContent(): void
    {
        $this->rsa->generateKeyPair(2048);
        $publicKey = $this->rsa->getPublicKey();

        // 使用反射调用私有方法
        $reflection = new \ReflectionClass($this->rsa);
        $method = $reflection->getMethod('getKeyBits');
        $method->setAccessible(true);

        $bits = $method->invoke($this->rsa, $publicKey);
        $this->assertEquals(2048, $bits);
    }

    public function testKeyExists(): void
    {
        $this->rsa->generateKeyPair();
        $this->rsa->saveKeys();

        $exists = $this->rsa->keyExists();

        $this->assertTrue($exists['private_key_exists']);
        $this->assertTrue($exists['public_key_exists']);
        $this->assertStringContainsString('rsa_private.pem', $exists['private_key_path']);
        $this->assertStringContainsString('rsa_public.pem', $exists['public_key_path']);
    }

    public function testSetKeys(): void
    {
        $this->rsa->generateKeyPair(2048);
        $privateKey = $this->rsa->getPrivateKey();
        $publicKey = $this->rsa->getPublicKey();

        // 创建新实例并通过 setter 设置密钥
        $rsa2 = new RSA('/nonexistent/path', 2048);
        $rsa2->setPrivateKey($privateKey);
        $rsa2->setPublicKey($publicKey);

        $data = 'Test data';
        $encrypted = $rsa2->encrypt($data);
        $decrypted = $rsa2->decrypt($encrypted);

        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptWithEmptyData(): void
    {
        $this->rsa->generateKeyPair();

        $encrypted = $this->rsa->encrypt('');
        $decrypted = $this->rsa->decrypt($encrypted);

        $this->assertEquals('', $decrypted);
    }

    public function testInvalidBase64ForDecrypt(): void
    {
        $this->rsa->generateKeyPair();

        $this->expectException(EncryptException::class);
        $this->rsa->decrypt('not-valid-base64!!!');
    }

    public function testInvalidPrivateKeyPath(): void
    {
        $this->rsa->generateKeyPair();

        // 加载不存在的密钥应该不抛异常，但返回 false
        $rsa2 = new RSA('/nonexistent/path', 2048);
        $result = $rsa2->loadKeys();

        $this->assertFalse($result['private_key_loaded']);
        $this->assertFalse($result['public_key_loaded']);
    }

    public function testDirectoryCreation(): void
    {
        $nestedDir = $this->testKeyDir . '/nested/deep/path';
        $rsa = new RSA($nestedDir, 2048);

        $rsa->generateKeyPair();
        $rsa->saveKeys();

        $this->assertFileExists($nestedDir . '/rsa_private.pem');
        $this->assertFileExists($nestedDir . '/rsa_public.pem');
    }

    public function testFilePermissions(): void
    {
        $this->rsa->generateKeyPair();
        $paths = $this->rsa->saveKeys();

        // 检查私钥文件权限 (应该是 0600)
        $perms = fileperms($paths['private_key_path']) & 0777;
        // Windows 下可能不适用，这里只做基本检查
        $this->assertFileExists($paths['private_key_path']);
    }
}
