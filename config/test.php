<?php

return [
    'aes' => [
        'cipher' => 'AES-256-CBC',
        'key_length' => 32,
        'iv_length' => 16,
    ],
    'rsa' => [
        'key_bits' => 2048,
        'key_dir' => sys_get_temp_dir() . '/test_keys',
        'private_key_file' => 'rsa_private.pem',
        'public_key_file' => 'rsa_public.pem',
        'sign_algorithm' => 'SHA256',
    ],
    'hybrid' => [
        'key_ttl' => 86400,
        'rsa_rotation_period' => 86400,
        'rsa_transition_period' => 3600,
        'rsa_keep_versions' => 2,
        'cache_prefix' => 'test_hybrid_enc:',
        'version_prefix' => 'test_rsa_version:',
        'client_id_header' => 'X-Client-ID',
        'auto_rotate' => false,
    ],
    'response_codes' => [
        'need_key_exchange' => 426,
        'need_reexchange' => 449,
    ],
];
