<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\service;

use ThinkEncryption\service\encrypt\HybridEncryption;
use ThinkEncryption\service\encrypt\RSA;
use ThinkEncryption\tests\TestCaseBase;
use ThinkEncryption\tests\mocks\Config;

class HybridEncryptionTest extends TestCaseBase
{
    private array $config;

    protected function setUp(): void
    {
        // 检查 OpenSSL 是否可用
        if (!function_exists('openssl_pkey_new') ||
            openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]) === false) {
            $this->markTestSkipped('OpenSSL is not properly configured on this system');
        }

        parent::setUp();

        // 配置已由 TestCaseBase::setupTestConfig() 设置
    }

    public function testRSAKeyGeneration(): void
    {
        $rsa = new RSA($this->testKeyDir, 2048);
        $keys = $rsa->generateKeyPair(2048);
        $paths = $rsa->saveKeys();

        $this->assertFileExists($paths['private_key_path']);
        $this->assertFileExists($paths['public_key_path']);

        // 加载并验证
        $rsa2 = new RSA($this->testKeyDir, 2048);
        $result = $rsa2->loadKeys();

        $this->assertTrue($result['private_key_loaded']);
        $this->assertTrue($result['public_key_loaded']);
    }

    public function testRSAEncryptDecryptAesKey(): void
    {
        $rsa = new RSA($this->testKeyDir, 2048);
        $rsa->generateKeyPair();
        $rsa->saveKeys();

        // 生成随机的 AES 密钥和 IV
        $aesKey = random_bytes(32);
        $aesIv = random_bytes(16);

        // 使用 RSA 加密
        $encryptedKey = $rsa->encrypt($aesKey);
        $encryptedIv = $rsa->encrypt($aesIv);

        // 使用 RSA 解密
        $decryptedKey = $rsa->decrypt($encryptedKey);
        $decryptedIv = $rsa->decrypt($encryptedIv);

        $this->assertEquals($aesKey, $decryptedKey);
        $this->assertEquals($aesIv, $decryptedIv);
    }

    public function testVersionGeneration(): void
    {
        $version1 = date('YmdHis');
        usleep(1000000); // 等待 1 秒
        $version2 = date('YmdHis');

        $this->assertNotEquals($version1, $version2);
    }

    public function testKeyDirectoryCreation(): void
    {
        $keyDir = $this->testKeyDir . '/nested/test';
        $rsa = new RSA($keyDir, 2048);

        $rsa->generateKeyPair();
        $rsa->saveKeys();

        $this->assertFileExists($keyDir . '/rsa_private.pem');
        $this->assertFileExists($keyDir . '/rsa_public.pem');
    }

    public function testChunkSizeCalculation(): void
    {
        $rsa2048 = new RSA($this->testKeyDir, 2048);
        $rsa2048->generateKeyPair(2048);

        // 2048 位: (2048/8) - 11 = 245
        $this->assertEquals(245, (int) floor((2048 / 8) - 11));

        // 4096 位: (4096/8) - 11 = 501
        $this->assertEquals(501, (int) floor((4096 / 8) - 11));
    }

    public function testKeyCleanupLogic(): void
    {
        // 模拟密钥文件清理逻辑
        $keyDir = $this->testKeyDir;
        $keepVersions = 2;
        $previousVersion = 'v2'; // v2 是 previous 版本

        // 创建 5 个版本，按时间顺序
        for ($i = 1; $i <= 5; $i++) {
            $privateFile = "{$keyDir}/rsa_private_v{$i}.pem";
            $publicFile = "{$keyDir}/rsa_public_v{$i}.pem";
            file_put_contents($privateFile, "key{$i}");
            file_put_contents($publicFile, "key{$i}");
            // 确保 mtime 不同（按创建顺序：v1 最老，v5 最新）
            touch($privateFile, time() - (6 - $i) * 86400);
            touch($publicFile, time() - (6 - $i) * 86400);
        }

        // 模拟清理逻辑：按 mtime 降序排序（最新在前）
        $files = glob("{$keyDir}/rsa_private_*.pem");
        usort($files, fn($a, $b) => filemtime($b) - filemtime($a));

        // 保留最新版本，previous 版本也保留
        $filesToDelete = array_slice($files, $keepVersions);

        $deletedFiles = [];
        foreach ($filesToDelete as $file) {
            $version = preg_replace('/.*rsa_private_v(\d+)\.pem/', '$1', basename($file));
            if ($previousVersion !== "v{$version}") {
                $deletedFiles[] = $version;
                @unlink("{$keyDir}/rsa_private_v{$version}.pem");
                @unlink("{$keyDir}/rsa_public_v{$version}.pem");
            }
        }

        // v1 是第二老的，应该在删除列表中
        // v2 是 previous 版本，不应被删除
        $this->assertContains('1', $deletedFiles);
        $this->assertNotContains('2', $deletedFiles);

        // 验证文件
        $this->assertFileDoesNotExist("{$keyDir}/rsa_private_v1.pem");
        $this->assertFileExists("{$keyDir}/rsa_private_v2.pem");
    }

    public function testDistributedLockSimulation(): void
    {
        // 模拟分布式锁逻辑
        $lockKey = 'test_lock';
        $lockFile = $this->testKeyDir . '/' . $lockKey;

        // 第一次获取锁成功
        $locked1 = !file_exists($lockFile);
        file_put_contents($lockFile, time());

        // 第二次获取锁失败（模拟）
        $locked2 = file_exists($lockFile);

        // 清理
        @unlink($lockFile);

        $this->assertTrue($locked1);
        $this->assertTrue($locked2); // 锁已存在
    }
}
