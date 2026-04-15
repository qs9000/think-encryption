<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\mocks;

/**
 * Config Facade 模拟
 */
class Config
{
    private static array $config = [];
    private static bool $initialized = false;

    public static function init(): void
    {
        if (self::$initialized) {
            return;
        }

        // 默认配置
        self::$config = [
            'encrypt' => [
                'aes' => [
                    'cipher' => 'AES-256-CBC',
                    'key_length' => 32,
                    'iv_length' => 16,
                ],
                'rsa' => [
                    'key_bits' => 2048,
                    'key_dir' => sys_get_temp_dir() . '/think-encryption-test-keys',
                    'private_key_file' => 'rsa_private.pem',
                    'public_key_file' => 'rsa_public.pem',
                    'sign_algorithm' => 'SHA256',
                ],
                'hybrid' => [
                    'key_ttl' => 86400,
                    'rsa_rotation_period' => 86400,
                    'rsa_transition_period' => 3600,
                    'rsa_keep_versions' => 2,
                    'cache_prefix' => 'test_hybrid_enc_' . uniqid() . ':',
                    'version_prefix' => 'test_rsa_version_' . uniqid() . ':',
                    'client_id_header' => 'X-Client-ID',
                    'auto_rotate' => false,
                ],
                'response_codes' => [
                    'need_key_exchange' => 426,
                    'need_reexchange' => 449,
                ],
            ],
        ];

        self::$initialized = true;
    }

    public static function get(string $name, $default = null)
    {
        self::init();

        return self::$config[$name] ?? $default;
    }

    public static function set(string $name, $value): void
    {
        self::$config[$name] = $value;
    }

    public static function reset(): void
    {
        self::$config = [];
        self::$initialized = false;
    }

    public static function getConfig(): array
    {
        self::init();
        return self::$config;
    }
}
