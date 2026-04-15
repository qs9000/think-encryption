<?php

return [
    'aes' => [
        'cipher' => 'AES-256-CBC',
        'key_length' => 32,
        'iv_length' => 16,
        'hmac_enabled' => true,           // 启用 HMAC 认证
    ],
    'rsa' => [
        'key_bits' => 3072,               // 2024年后推荐使用3072+
        'key_dir' => root_path() . 'storage/keys',  // Web 不可访问的安全目录
        'private_key_file' => 'rsa_private.pem',
        'public_key_file' => 'rsa_public.pem',
        'sign_algorithm' => 'SHA256',
    ],
    'hybrid' => [
        'key_ttl' => 86400,
        'rsa_rotation_period' => 2592000, // 30天，大于 TTL
        'rsa_transition_period' => 3600,
        'rsa_keep_versions' => 2,
        'cache_prefix' => 'hybrid_enc:',
        'version_prefix' => 'rsa_version:',
        'client_id_header' => 'X-Client-ID',
        'auto_rotate' => false,
        // 客户端密钥存储加密配置
        'client_key_encryption' => true,
        // 密钥轮换锁的超时时间（秒）
        'rotate_lock_ttl' => 120,
    ],
    // 中间件配置
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
];
