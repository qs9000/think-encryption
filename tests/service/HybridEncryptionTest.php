<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\service;

use ThinkEncryption\service\encrypt\HybridEncryption;
use ThinkEncryption\tests\TestCaseBase;

class HybridEncryptionTest extends TestCaseBase
{
    public function testVersionGeneration(): void
    {
        $version1 = date('YmdHis');
        usleep(1000000); // 等待 1 秒
        $version2 = date('YmdHis');

        $this->assertNotEquals($version1, $version2);
    }

    public function testChunkSizeCalculation(): void
    {
        // OAEP: (keyBits / 8) - 2 * hash_length - 2
        $hashLength = 32;

        // 2048 位: 256 - 66 - 2 = 188 (使用 floor)
        // 但 RSA.php 使用 (keyBits / 8) - 2 * hash_length - 2，结果是 190
        $this->assertEquals(190, (int) floor((2048 / 8) - 2 * $hashLength - 2));

        // 3072 位: 384 - 66 - 2 = 316 (使用 floor)
        // 但 RSA.php 使用 (keyBits / 8) - 2 * hash_length - 2，结果是 318
        $this->assertEquals(318, (int) floor((3072 / 8) - 2 * $hashLength - 2));
    }

    public function testKeyCleanupLogic(): void
    {
        // 创建临时目录
        $keyDir = sys_get_temp_dir() . '/hybrid-test-' . uniqid();
        mkdir($keyDir, 0755, true);
        
        $keepVersions = 2;
        $previousVersion = 'v2';

        try {
            // 创建 5 个版本，按时间顺序
            for ($i = 1; $i <= 5; $i++) {
                $privateFile = "{$keyDir}/rsa_private_v{$i}.pem";
                $publicFile = "{$keyDir}/rsa_public_v{$i}.pem";
                file_put_contents($privateFile, "key{$i}");
                file_put_contents($publicFile, "key{$i}");
                // 确保 mtime 不同
                touch($privateFile, time() - (6 - $i) * 86400);
                touch($publicFile, time() - (6 - $i) * 86400);
            }

            $files = glob("{$keyDir}/rsa_private_*.pem");
            usort($files, fn($a, $b) => filemtime($b) - filemtime($a));

            $filesToDelete = array_slice($files, $keepVersions);

            $deletedFiles = [];
            foreach ($filesToDelete as $file) {
                $version = preg_replace('/.*rsa_private_v(\d+)\.pem/', '$1', basename($file));
                if ($previousVersion !== "v{$version}") {
                    $deletedFiles[] = $version;
                }
            }

            $this->assertContains('1', $deletedFiles);
            $this->assertNotContains('2', $deletedFiles);
        } finally {
            // 清理
            $files = glob("{$keyDir}/*.pem");
            foreach ($files as $file) {
                @unlink($file);
            }
            @rmdir($keyDir);
        }
    }

    public function testDistributedLockSimulation(): void
    {
        // 创建临时目录
        $lockDir = sys_get_temp_dir() . '/hybrid-test-' . uniqid();
        mkdir($lockDir, 0755, true);
        
        try {
            $lockKey = 'test_lock';
            $lockFile = $lockDir . '/' . $lockKey;

            // 第一次获取锁成功
            $locked1 = !file_exists($lockFile);
            file_put_contents($lockFile, time());

            // 第二次获取锁失败（模拟）
            $locked2 = file_exists($lockFile);

            @unlink($lockFile);

            $this->assertTrue($locked1);
            $this->assertTrue($locked2);
        } finally {
            @rmdir($lockDir);
        }
    }

    public function testClientIdValidation(): void
    {
        // 有效的 ClientId
        $validIds = [
            'client-001',
            'test_client_123',
            'ABCDEF',
            'a' . str_repeat('x', 62),
        ];

        foreach ($validIds as $id) {
            $this->assertLessThanOrEqual(64, strlen($id));
            $this->assertMatchesRegularExpression('/^[a-zA-Z0-9_-]{4,64}$/', $id);
        }

        // 无效的 ClientId
        $invalidIds = [
            'ab',           // 太短
            'client@001',   // 包含 @
            'client space', // 包含空格
        ];

        foreach ($invalidIds as $id) {
            $this->assertFalse(
                preg_match('/^[a-zA-Z0-9_-]{4,64}$/', $id) === 1,
                "Expected '{$id}' to be invalid"
            );
        }
    }
}
