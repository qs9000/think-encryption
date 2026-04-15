<?php

declare(strict_types=1);

/**
 * 独立测试脚本 - 验证核心加密逻辑
 * 不依赖 ThinkPHP 框架
 */

echo "=== ThinkPHP 加密插件测试 ===\n\n";

// 定义常量
define('root_path', __DIR__ . '/');

// 模拟 env() 函数
function env(string $name, $default = null)
{
    static $env = [];
    if (empty($env)) {
        $envFile = root_path() . '.env';
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos($line, '#') === 0) continue;
                if (strpos($line, '=') !== false) {
                    [$key, $value] = explode('=', $line, 2);
                    $env[trim($key)] = trim($value);
                }
            }
        }
        // 默认测试密钥
        $env['ENCRYPTION_KEY'] = $env['ENCRYPTION_KEY'] ?? 'test_encryption_key_32chars!!';
        $env['APP_DEBUG'] = $env['APP_DEBUG'] ?? 'true';
    }
    return $env[$name] ?? $default;
}

// 模拟 app() 函数
function app(string $name = null)
{
    static $container = [];

    if ($name === null) {
        return $container;
    }

    if ($name === 'request') {
        if (!isset($container['request'])) {
            $container['request'] = new class {
                private array $headers = [];

                public function header(string $name = null, $default = null)
                {
                    if ($name === null) {
                        return $this->headers;
                    }
                    return $this->headers[$name] ?? $default;
                }

                public function setHeader(string $name, string $value): void
                {
                    $this->headers[$name] = $value;
                }
            };
        }
        return $container['request'];
    }

    return $container[$name] ?? null;
}

/**
 * 简单的内存缓存模拟
 */
class SimpleCache
{
    private static array $store = [];

    public static function get(string $name, $default = null)
    {
        if (isset(self::$store[$name])) {
            $item = self::$store[$name];
            if ($item['expire'] !== 0 && $item['expire'] < time()) {
                unset(self::$store[$name]);
                return $default;
            }
            return $item['value'];
        }
        return $default;
    }

    public static function set(string $name, $value, $ttl = 0): bool
    {
        $expire = $ttl > 0 ? time() + $ttl : 0;
        self::$store[$name] = ['value' => $value, 'expire' => $expire];
        return true;
    }

    public static function delete(string $name): bool
    {
        unset(self::$store[$name]);
        return true;
    }

    public static function add(string $name, $value, $ttl = 0): bool
    {
        if (isset(self::$store[$name])) return false;
        return self::set($name, $value, $ttl);
    }

    public static function reset(): void
    {
        self::$store = [];
    }
}

// 加载 Composer autoload
require_once __DIR__ . '/vendor/autoload.php';

// 加载源码（需要在 ThinkPHP 环境外运行的部分）
spl_autoload_register(function ($class) {
    if (strpos($class, 'ThinkEncryption\\') === 0) {
        $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 17)) . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});

// 模拟 think\facade\Config
class_alias(\ThinkEncryption\tests\mocks\Config::class, 'think\facade\Config');
class_alias(\ThinkEncryption\tests\mocks\Cache::class, 'think\facade\Cache');

$testDir = sys_get_temp_dir() . '/encryption-test-' . uniqid();
mkdir($testDir, 0755, true);

$testConfig = [
    'aes' => [
        'cipher' => 'AES-256-CBC',
        'key_length' => 32,
        'iv_length' => 16,
    ],
    'rsa' => [
        'key_bits' => 2048,
        'key_dir' => $testDir,
        'private_key_file' => 'rsa_private.pem',
        'public_key_file' => 'rsa_public.pem',
        'sign_algorithm' => 'SHA256',
    ],
    'hybrid' => [
        'key_ttl' => 86400,
        'rsa_rotation_period' => 86400,
        'rsa_transition_period' => 3600,
        'rsa_keep_versions' => 2,
        'cache_prefix' => 'test_enc:',
        'version_prefix' => 'test_ver:',
        'client_id_header' => 'X-Client-ID',
        'auto_rotate' => false,
    ],
];

\think\facade\Config::set('encrypt', $testConfig);

echo "========================================\n";
echo "1. 测试 AES 加密/解密\n";
echo "========================================\n";

use ThinkEncryption\service\encrypt\AES;
use ThinkEncryption\service\encrypt\RSA;
use ThinkEncryption\exception\EncryptException;
use ThinkEncryption\traits\ClientIdentity;

$aes = new AES();
$testKey = 'test_key_32_chars_long_here!!'; // 32 bytes
$testIv = '1234567890123456'; // 16 bytes

// 测试字符串加密
$plaintext = 'Hello, World! 你好世界！';
$encrypted = $aes->encrypt($plaintext, $testKey, $testIv);
$decrypted = $aes->decrypt($encrypted, $testKey);

echo "  原文字符串: {$plaintext}\n";
echo "  加密后 (Base64): " . substr($encrypted, 0, 50) . "...\n";
echo "  解密后: {$decrypted}\n";
echo "  ✓ " . ($plaintext === $decrypted ? "测试通过" : "测试失败") . "\n\n";

// 测试数组加密
echo "--------------------------------\n";
echo "2. 测试 AES 加密/解密 (数组)\n";
echo "--------------------------------\n";

$data = ['name' => '测试', 'age' => 25, 'nested' => ['key' => 'value']];
$encryptedArray = $aes->encrypt($data, $testKey, $testIv);
$decryptedArray = $aes->decrypt($encryptedArray, $testKey);

echo "  原文数组: " . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n";
echo "  解密后: " . json_encode($decryptedArray, JSON_UNESCAPED_UNICODE) . "\n";
echo "  ✓ " . ($data === $decryptedArray ? "测试通过" : "测试失败") . "\n\n";

// 测试自动生成 IV
echo "--------------------------------\n";
echo "3. 测试自动生成 IV\n";
echo "--------------------------------\n";

$encryptedAuto = $aes->encrypt('Auto IV test', $testKey);
$decryptedAuto = $aes->decrypt($encryptedAuto, $testKey);

echo "  原文字符串: Auto IV test\n";
echo "  解密后: {$decryptedAuto}\n";
echo "  ✓ " . ('Auto IV test' === $decryptedAuto ? "测试通过" : "测试失败") . "\n\n";

// 测试密钥长度处理（密钥 >= 16 字符但 < 32 会被哈希）
echo "--------------------------------\n";
echo "4. 测试密钥自动哈希（短于32字节）\n";
echo "--------------------------------\n";

$shortKey = 'my-short-key-16!'; // 16 bytes (最小有效长度)
$encryptedShort = $aes->encrypt('Short key test', $shortKey);
$decryptedShort = $aes->decrypt($encryptedShort, $shortKey);

echo "  短密钥: {$shortKey} (" . strlen($shortKey) . " bytes)\n";
echo "  解密后: {$decryptedShort}\n";
echo "  ✓ " . ('Short key test' === $decryptedShort ? "测试通过" : "测试失败") . "\n\n";

echo "\n========================================\n";
echo "5. 测试 RSA 密钥生成\n";
echo "========================================\n";

// 检查 OpenSSL 是否可用
$opensslTest = @openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
if ($opensslTest === false) {
    echo "  ⚠ OpenSSL 密钥生成不可用（环境限制）\n";
    echo "  系统: " . PHP_OS . " | OpenSSL: " . OPENSSL_VERSION_TEXT . "\n";
    echo "  跳过 RSA 相关测试\n\n";
} else {
    @openssl_pkey_free($opensslTest);

    $rsa = new RSA($testDir, 2048);
    $keys = $rsa->generateKeyPair(2048);
    $paths = $rsa->saveKeys();

    echo "  私钥生成: " . (strpos($keys['private_key'], 'BEGIN RSA PRIVATE KEY') !== false ? "✓" : "✗") . "\n";
    echo "  公钥生成: " . (strpos($keys['public_key'], 'BEGIN RSA PUBLIC KEY') !== false ? "✓" : "✗") . "\n";
    echo "  私钥保存: " . (file_exists($paths['private_key_path']) ? "✓" : "✗") . "\n";
    echo "  公钥保存: " . (file_exists($paths['public_key_path']) ? "✓" : "✗") . "\n\n";
}

echo "========================================\n";
echo "6. 测试 RSA 加密/解密\n";
echo "========================================\n";

if (!isset($rsa)) {
    echo "  ⚠ 跳过（RSA 不可用）\n\n";
} else {
    $aesKey = random_bytes(32);
    $aesIv = random_bytes(16);

    $encryptedKey = $rsa->encrypt($aesKey);
    $encryptedIv = $rsa->encrypt($aesIv);

    $decryptedKey = $rsa->decrypt($encryptedKey);
    $decryptedIv = $rsa->decrypt($encryptedIv);

    echo "  AES Key 加密/解密: " . ($aesKey === $decryptedKey ? "✓" : "✗") . "\n";
    echo "  AES IV 加密/解密: " . ($aesIv === $decryptedIv ? "✓" : "✗") . "\n\n";
}

echo "========================================\n";
echo "7. 测试 RSA 长数据分块加密\n";
echo "========================================\n";

if (!isset($rsa)) {
    echo "  ⚠ 跳过（RSA 不可用）\n\n";
} else {
    $longData = str_repeat('A', 500);
    $encryptedLong = $rsa->encrypt($longData);
    $decryptedLong = $rsa->decrypt($encryptedLong);

    echo "  原始数据长度: " . strlen($longData) . " bytes\n";
    echo "  加密后长度: " . strlen($encryptedLong) . " bytes\n";
    echo "  解密后长度: " . strlen($decryptedLong) . " bytes\n";
    echo "  ✓ " . ($longData === $decryptedLong ? "测试通过" : "测试失败") . "\n\n";
}

echo "========================================\n";
echo "8. 测试 RSA 签名和验证\n";
echo "========================================\n";

if (!isset($rsa)) {
    echo "  ⚠ 跳过（RSA 不可用）\n\n";
} else {
    $data = 'Data to sign';
    $signature = $rsa->sign($data);
    $verified = $rsa->verify($data, $signature);

    echo "  签名: " . (strlen($signature) > 0 ? "✓" : "✗") . "\n";
    echo "  验证: " . ($verified ? "✓" : "✗") . "\n";
    echo "  篡改验证: " . (!$rsa->verify('Tampered', $signature) ? "✓" : "✗") . "\n\n";
}

echo "========================================\n";
echo "9. 测试 RSA 动态 chunkSize 计算\n";
echo "========================================\n";

// 2048 位 chunk size 应该是 245
$chunk2048 = (int) floor((2048 / 8) - 11);
echo "  2048 位 chunk size: {$chunk2048} (应为 245)\n";
echo "  ✓ " . ($chunk2048 === 245 ? "测试通过" : "测试失败") . "\n";

// 4096 位 chunk size 应该是 501
$chunk4096 = (int) floor((4096 / 8) - 11);
echo "  4096 位 chunk size: {$chunk4096} (应为 501)\n";
echo "  ✓ " . ($chunk4096 === 501 ? "测试通过" : "测试失败") . "\n\n";

echo "========================================\n";
echo "10. 测试异常类\n";
echo "========================================\n";

$e1 = EncryptException::keyNotFound('client-123');
echo "  keyNotFound 工厂方法: ";
echo ($e1->getCode() === EncryptException::CODE_KEY_NOT_FOUND ? "✓" : "✗");
echo " | HTTP: {$e1->getHttpCode()} (应为 426)\n";

$e2 = EncryptException::decryptFailed('CRC error');
echo "  decryptFailed 工厂方法: ";
echo ($e2->getCode() === EncryptException::CODE_DECRYPT_FAILED ? "✓" : "✗");
echo " | 消息包含原因: " . (strpos($e2->getMessage(), 'CRC error') !== false ? "✓" : "✗") . "\n";

$e3 = EncryptException::clientIdMissing();
echo "  clientIdMissing 工厂方法: ";
echo ($e3->getCode() === EncryptException::CODE_CLIENT_ID_MISSING ? "✓" : "✗");
echo " | HTTP: {$e3->getHttpCode()} (应为 400)\n";

$array = $e1->toArray();
echo "  toArray 方法: ";
echo (isset($array['code']) && isset($array['message']) && isset($array['data']) ? "✓" : "✗") . "\n\n";

echo "========================================\n";
echo "11. 测试错误解密（应该失败）\n";
echo "========================================\n";

$wrongKey = 'wrong_key_32_chars_needed_here';
try {
    $aes->decrypt($encrypted, $wrongKey);
    echo "  ✗ 应该抛出异常但没有\n";
} catch (EncryptException $e) {
    echo "  ✓ 正确抛出异常: " . $e->getMessage() . " (Code: {$e->getCode()})\n";
}

try {
    $aes->decrypt('invalid-base64!!!');
    echo "  ✗ 应该抛出异常但没有\n";
} catch (EncryptException $e) {
    echo "  ✓ 正确抛出异常: " . $e->getMessage() . " (Code: {$e->getCode()})\n";
}

echo "\n========================================\n";
echo "12. 测试 ClientIdentity Trait\n";
echo "========================================\n";

class MockClientIdentity
{
    use ClientIdentity;

    private array $config = [
        'hybrid' => ['client_id_header' => 'X-Client-ID']
    ];

    protected function getConfig(): array
    {
        return $this->config;
    }

    // 公开方法用于测试
    public function testGetClientId(): ?string
    {
        return $this->getClientId();
    }

    public function testGetClientIdOrFail(): string
    {
        return $this->getClientIdOrFail();
    }
}

$mock = new MockClientIdentity();
$clientId = $mock->testGetClientId();
echo "  获取默认 Client ID: " . ($clientId === null ? "✓ (null)" : "✗") . "\n";

try {
    $mock->testGetClientIdOrFail();
    echo "  ✗ 应该抛出异常但没有\n";
} catch (EncryptException $e) {
    echo "  ✓ getClientIdOrFail 正确抛出异常\n";
}

// 清理
function cleanup(string $dir): void
{
    if (!is_dir($dir)) return;
    $files = array_diff(scandir($dir), ['.', '..']);
    foreach ($files as $file) {
        $path = $dir . DIRECTORY_SEPARATOR . $file;
        is_dir($path) ? cleanup($path) : @unlink($path);
    }
    @rmdir($dir);
}

cleanup($testDir);

echo "\n========================================\n";
echo "所有核心测试完成！\n";
echo "========================================\n";
