<?php

declare(strict_types=1);

namespace ThinkEncryption\tests;

use ThinkEncryption\service\encrypt\AES;
use ThinkEncryption\service\encrypt\RSA;

/**
 * 性能测试
 * 注意：Windows 环境下 OpenSSL 有并发限制，密钥生成测试可能失败
 */
class PerformanceTest extends TestCaseBase
{
    private AES $aes;
    private ?string $rsaPrivateKey = null;
    private ?string $rsaPublicKey = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->aes = new AES();
    }

    /**
     * 初始化 RSA 密钥（如果尚未初始化）
     */
    private function initRsaKeys(): void
    {
        if ($this->rsaPrivateKey === null) {
            $rsa = new RSA($this->testKeyDir, 2048);
            $keys = $rsa->generateKeyPair(2048);
            $this->rsaPrivateKey = $keys['private_key'];
            $this->rsaPublicKey = $keys['public_key'];
        }
    }

    /**
     * 格式化字节大小
     */
    private function formatBytes(int $bytes): string
    {
        if ($bytes < 1024) {
            return $bytes . ' B';
        }
        if ($bytes < 1024 * 1024) {
            return round($bytes / 1024, 2) . ' KB';
        }
        return round($bytes / (1024 * 1024), 2) . ' MB';
    }

    /**
     * 格式化时间
     */
    private function formatTime(float $seconds): string
    {
        if ($seconds < 0.001) {
            return round($seconds * 1000000, 2) . ' μs';
        }
        if ($seconds < 1) {
            return round($seconds * 1000, 2) . ' ms';
        }
        return round($seconds, 2) . ' s';
    }

    /**
     * 多次运行取平均值
     */
    private function benchmark(callable $callback, int $iterations = 10): array
    {
        $times = [];

        for ($i = 0; $i < $iterations; $i++) {
            $startTime = hrtime(true);
            $callback();
            $endTime = hrtime(true);
            $times[] = ($endTime - $startTime) / 1e9;
        }

        $avgTime = array_sum($times) / count($times);
        $minTime = min($times);
        $maxTime = max($times);

        return [
            'avg' => $avgTime,
            'min' => $minTime,
            'max' => $maxTime,
        ];
    }

    // ==================== AES 性能测试 ====================

    public function testAesEncryptDecrypt(): void
    {
        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "AES-256-CBC 加密/解密性能测试\n";
        echo str_repeat('=', 60) . "\n";

        $testSizes = [
            '16B' => 16,
            '64B' => 64,
            '256B' => 256,
            '1KB' => 1024,
            '10KB' => 10 * 1024,
            '100KB' => 100 * 1024,
            '1MB' => 1024 * 1024,
        ];

        foreach ($testSizes as $name => $size) {
            $data = ['test' => str_repeat('a', $size)];

            $encryptResult = $this->benchmark(function () use ($data) {
                $this->aes->encrypt($data);
            }, 100);

            $encrypted = $this->aes->encrypt($data);

            $decryptResult = $this->benchmark(function () use ($encrypted) {
                $this->aes->decrypt($encrypted);
            }, 100);

            echo "\n[{$name}] JSON数据 ~{$size} bytes\n";
            echo "  加密: " . $this->formatTime($encryptResult['avg']) . " (min: " . $this->formatTime($encryptResult['min']) . ", max: " . $this->formatTime($encryptResult['max']) . ")\n";
            echo "  解密: " . $this->formatTime($decryptResult['avg']) . " (min: " . $this->formatTime($decryptResult['min']) . ", max: " . $this->formatTime($decryptResult['max']) . ")\n";
        }

        $this->assertTrue(true);
    }

    // ==================== RSA 性能测试 ====================

    /**
     * @group slow
     * @group rsa
     */
    public function testRsaEncryptDecrypt(): void
    {
        $this->markTestSkipped('Windows PHP 8.4 OpenSSL 兼容性问题，跳过 RSA 测试');

        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "RSA-2048 加密/解密性能测试\n";
        echo str_repeat('=', 60) . "\n";

        $this->initRsaKeys();

        $testSizes = [
            '16B' => 16,
            '64B' => 64,
            '200B' => 200,
        ];

        foreach ($testSizes as $name => $size) {
            $data = random_bytes($size);

            $rsa = new RSA($this->testKeyDir, 2048);
            $rsa->setPrivateKey($this->rsaPrivateKey);
            $rsa->setPublicKey($this->rsaPublicKey);

            $encryptResult = $this->benchmark(function () use ($rsa, $data) {
                $rsa->encrypt($data);
            }, 50);

            $encrypted = $rsa->encrypt($data);

            $decryptResult = $this->benchmark(function () use ($rsa, $encrypted) {
                $rsa->decrypt($encrypted);
            }, 50);

            echo "\n[{$name}] 数据大小: {$size} bytes\n";
            echo "  加密: " . $this->formatTime($encryptResult['avg']) . " (min: " . $this->formatTime($encryptResult['min']) . ", max: " . $this->formatTime($encryptResult['max']) . ")\n";
            echo "  解密: " . $this->formatTime($decryptResult['avg']) . " (min: " . $this->formatTime($decryptResult['min']) . ", max: " . $this->formatTime($decryptResult['max']) . ")\n";
        }

        $this->assertTrue(true);
    }

    // ==================== 吞吐量测试 ====================

    public function testThroughput(): void
    {
        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "吞吐量测试 (ops/second)\n";
        echo str_repeat('=', 60) . "\n";

        $secret = base64_encode(random_bytes(32));

        echo "\n--- AES-256-CBC ---\n";

        // 1KB 数据
        $data1k = ['test' => str_repeat('a', 1024)];
        $start = microtime(true);
        $count = 0;
        while (microtime(true) - $start < 1.0) {
            $this->aes->encrypt($data1k, $secret);
            $count++;
        }
        echo "  1KB数据加密: " . $count . " ops/s\n";

        $enc1k = $this->aes->encrypt($data1k, $secret);
        $start = microtime(true);
        $count = 0;
        while (microtime(true) - $start < 1.0) {
            $this->aes->decrypt($enc1k, $secret);
            $count++;
        }
        echo "  1KB数据解密: " . $count . " ops/s\n";

        // 100KB 数据
        $data100k = ['test' => str_repeat('a', 100 * 1024)];
        $start = microtime(true);
        $count = 0;
        while (microtime(true) - $start < 1.0) {
            $this->aes->encrypt($data100k, $secret);
            $count++;
        }
        echo "  100KB数据加密: " . $count . " ops/s\n";

        $enc100k = $this->aes->encrypt($data100k, $secret);
        $start = microtime(true);
        $count = 0;
        while (microtime(true) - $start < 1.0) {
            $this->aes->decrypt($enc100k, $secret);
            $count++;
        }
        echo "  100KB数据解密: " . $count . " ops/s\n";

        $this->assertTrue(true);
    }

    // ==================== 内存测试 ====================

    public function testMemoryUsage(): void
    {
        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "内存使用测试\n";
        echo str_repeat('=', 60) . "\n";

        echo "\nAES 加密大文件 (10MB 数据):\n";
        gc_collect_cycles();
        $memBefore = memory_get_usage();

        $largeData = ['data' => str_repeat('x', 10 * 1024 * 1024)];
        $encrypted = $this->aes->encrypt($largeData);

        $memAfter = memory_get_usage();
        echo "  加密后内存占用: " . $this->formatBytes($memAfter - $memBefore) . "\n";
        echo "  加密后数据大小: " . $this->formatBytes(strlen($encrypted)) . "\n";

        unset($largeData, $encrypted);
        gc_collect_cycles();

        echo "\n峰值内存使用: " . $this->formatBytes(memory_get_peak_usage()) . "\n";

        $this->assertTrue(true);
    }

    // ==================== 稳定性测试 ====================

    public function testStability(): void
    {
        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "连续操作性能稳定性测试\n";
        echo str_repeat('=', 60) . "\n";

        $iterations = 30;
        $times = [];

        echo "\n执行 {$iterations} 次 AES 加密/解密循环:\n";

        $data = ['test' => str_repeat('a', 1024)];
        for ($i = 0; $i < $iterations; $i++) {
            $start = hrtime(true);
            $encrypted = $this->aes->encrypt($data);
            $decrypted = $this->aes->decrypt($encrypted);
            $end = hrtime(true);

            $times[] = ($end - $start) / 1e9;

            $this->assertEquals($data, $decrypted);
        }

        $avg = array_sum($times) / count($times);
        $min = min($times);
        $max = max($times);

        echo "平均耗时: " . $this->formatTime($avg) . "\n";
        echo "最快耗时: " . $this->formatTime($min) . "\n";
        echo "最慢耗时: " . $this->formatTime($max) . "\n";
        echo "波动率:   " . round((($max - $min) / $avg) * 100, 2) . "%\n";

        $this->assertTrue(true);
    }

    // ==================== 密钥生成测试（独立运行）====================

    /**
     * @group slow
     * @group rsa
     */
    public function testRsaKeyGeneration(): void
    {
        $this->markTestSkipped('Windows PHP 8.4 OpenSSL 兼容性问题，跳过 RSA 测试');

        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "RSA 密钥生成性能测试\n";
        echo str_repeat('=', 60) . "\n";

        // RSA-2048
        echo "\nRSA-2048:\n";
        $keyDir1 = $this->testKeyDir . '/rsa2048_' . uniqid();
        mkdir($keyDir1, 0755, true);

        $start = hrtime(true);
        $rsa = new RSA($keyDir1, 2048);
        $keys = $rsa->generateKeyPair(2048);
        $end = hrtime(true);

        echo "  生成耗时: " . $this->formatTime(($end - $start) / 1e9) . "\n";
        echo "  公钥长度: " . $this->formatBytes(strlen($keys['public_key'])) . "\n";
        echo "  私钥长度: " . $this->formatBytes(strlen($keys['private_key'])) . "\n";

        // RSA-3072
        echo "\nRSA-3072:\n";
        $keyDir2 = $this->testKeyDir . '/rsa3072_' . uniqid();
        mkdir($keyDir2, 0755, true);

        $start = hrtime(true);
        $rsa = new RSA($keyDir2, 3072);
        $keys = $rsa->generateKeyPair(3072);
        $end = hrtime(true);

        echo "  生成耗时: " . $this->formatTime(($end - $start) / 1e9) . "\n";
        echo "  公钥长度: " . $this->formatBytes(strlen($keys['public_key'])) . "\n";
        echo "  私钥长度: " . $this->formatBytes(strlen($keys['private_key'])) . "\n";

        $this->assertTrue(true);
    }

    // ==================== 混合加密测试 ====================

    /**
     * @group slow
     * @group rsa
     */
    public function testHybridEncryption(): void
    {
        $this->markTestSkipped('Windows PHP 8.4 OpenSSL 兼容性问题，跳过 RSA 测试');

        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "混合加密流程性能测试\n";
        echo str_repeat('=', 60) . "\n";

        $this->initRsaKeys();

        $rsa = new RSA($this->testKeyDir, 2048);
        $rsa->setPrivateKey($this->rsaPrivateKey);
        $rsa->setPublicKey($this->rsaPublicKey);

        // 模拟密钥交换
        $aesKey = random_bytes(32);
        $iv = random_bytes(16);

        echo "\n--- 密钥交换阶段 ---\n";

        $start = hrtime(true);
        $encryptedAesKey = $rsa->encrypt($aesKey);
        $encryptedIv = $rsa->encrypt($iv);
        $keyExchangeTime = (hrtime(true) - $start) / 1e9;
        echo "  RSA加密(密钥+IV): " . $this->formatTime($keyExchangeTime) . "\n";

        $secret = base64_encode($aesKey);

        // 模拟数据加密
        $testData = ['username' => 'test_user', 'data' => str_repeat('x', 1000)];

        echo "\n--- 数据加密阶段 ---\n";

        $encryptResult = $this->benchmark(function () use ($testData, $secret) {
            $this->aes->encrypt($testData, $secret);
        }, 100);
        echo "  AES加密(1KB):    " . $this->formatTime($encryptResult['avg']) . "\n";

        $encryptedData = $this->aes->encrypt($testData, $secret);

        $decryptResult = $this->benchmark(function () use ($encryptedData, $secret) {
            $this->aes->decrypt($encryptedData, $secret);
        }, 100);
        echo "  AES解密(1KB):    " . $this->formatTime($decryptResult['avg']) . "\n";

        // 模拟密钥解密
        echo "\n--- 密钥解密阶段 ---\n";

        $start = hrtime(true);
        $rsa->decrypt($encryptedAesKey);
        $rsa->decrypt($encryptedIv);
        $keyDecryptTime = (hrtime(true) - $start) / 1e9;
        echo "  RSA解密(密钥+IV): " . $this->formatTime($keyDecryptTime) . "\n";

        $this->assertTrue(true);
    }

    // ==================== RSA vs AES 对比 ====================

    /**
     * @group slow
     * @group rsa
     */
    public function testRsaVsAesComparison(): void
    {
        $this->markTestSkipped('Windows PHP 8.4 OpenSSL 兼容性问题，跳过 RSA 测试');

        echo "\n\n" . str_repeat('=', 60) . "\n";
        echo "RSA vs AES 性能对比\n";
        echo str_repeat('=', 60) . "\n";

        $this->initRsaKeys();

        $rsa = new RSA($this->testKeyDir, 2048);
        $rsa->setPrivateKey($this->rsaPrivateKey);
        $rsa->setPublicKey($this->rsaPublicKey);

        $sizes = [
            '100B' => 100,
            '1KB' => 1024,
        ];

        echo "\n";
        echo str_pad("数据大小", 10);
        echo str_pad("RSA加密", 15);
        echo str_pad("AES加密", 15);
        echo str_pad("AES快", 10);
        echo "\n";
        echo str_repeat('-', 50) . "\n";

        foreach ($sizes as $name => $size) {
            $data = random_bytes($size);

            $rsaResult = $this->benchmark(function () use ($rsa, $data) {
                $rsa->encrypt($data);
            }, 30);

            $aesResult = $this->benchmark(function () use ($data) {
                $secret = base64_encode(random_bytes(32));
                $this->aes->encrypt(['data' => $data], $secret);
            }, 100);

            $ratio = $rsaResult['avg'] / $aesResult['avg'];

            echo str_pad($name, 10);
            echo str_pad($this->formatTime($rsaResult['avg']), 15);
            echo str_pad($this->formatTime($aesResult['avg']), 15);
            echo str_pad("{$ratio}x", 10);
            echo "\n";
        }

        $this->assertTrue(true);
    }
}
