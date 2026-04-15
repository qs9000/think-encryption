<?php

declare(strict_types=1);

namespace ThinkEncryption\tests;

use PHPUnit\Framework\TestCase;
use ThinkEncryption\tests\mocks\Config;
use ThinkEncryption\tests\mocks\Cache;

abstract class TestCaseBase extends TestCase
{
    protected string $testKeyDir;
    protected string $testCachePrefix;
    protected string $testVersionPrefix;
    protected string $testClientId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->testCachePrefix = 'test_enc_' . uniqid();
        $this->testClientId = 'test-client-' . uniqid();

        // 重置 Mock
        Config::reset();
        Cache::reset();

        // 创建测试用临时密钥目录
        $this->testKeyDir = sys_get_temp_dir() . '/think-encryption-test-' . uniqid();

        if (!is_dir($this->testKeyDir)) {
            mkdir($this->testKeyDir, 0755, true);
        }

        $this->setupTestConfig();
    }

    protected function tearDown(): void
    {
        $this->cleanupDirectory($this->testKeyDir);
        Config::reset();
        Cache::reset();

        parent::tearDown();
    }

    protected function setupTestConfig(): void
    {
        $this->testVersionPrefix = 'test_rsa_version_' . uniqid() . ':';

        Config::set('encrypt', [
            'aes' => [
                'cipher' => 'AES-256-CBC',
                'key_length' => 32,
                'iv_length' => 16,
                'hmac_enabled' => true,
            ],
            'rsa' => [
                'key_bits' => 2048,
                'key_dir' => $this->testKeyDir,
                'private_key_file' => 'rsa_private.pem',
                'public_key_file' => 'rsa_public.pem',
                'sign_algorithm' => 'SHA256',
            ],
            'hybrid' => [
                'key_ttl' => 86400,
                'rsa_rotation_period' => 2592000,
                'rsa_transition_period' => 3600,
                'rsa_keep_versions' => 2,
                'cache_prefix' => $this->testCachePrefix,
                'version_prefix' => $this->testVersionPrefix,
                'client_id_header' => 'X-Client-ID',
                'auto_rotate' => false,
                'client_key_encryption' => true,
            ],
            'middleware' => [
                'exclude_paths' => [
                    '/api/encryption/public-key',
                    '/api/encryption/exchange-keys',
                ],
            ],
            'response_codes' => [
                'need_key_exchange' => 426,
                'need_reexchange' => 449,
            ],
        ]);
    }

    protected function cleanupDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . DIRECTORY_SEPARATOR . $file;
            if (is_dir($path)) {
                $this->cleanupDirectory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    protected function generateRandomString(int $length = 32): string
    {
        return bin2hex(random_bytes($length / 2));
    }
}
