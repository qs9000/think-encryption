# ThinkPHP 混合加密插件

基于 RSA + AES 的混合加密方案，支持密钥自动轮换，适用于前后端分离项目。

## 特性

- **混合加密**：RSA 非对称加密安全交换 AES 对称密钥
- **密钥轮换**：支持自动/手动 RSA 密钥轮换，过渡期确保平滑切换
- **分布式支持**：使用 Redis 存储客户端密钥，支持分布式部署
- **统一异常**：完整的 EncryptException 异常处理体系
- **中间件集成**：开箱即用的加密请求中间件
- **完整测试**：包含 38+ 单元测试，覆盖核心功能

## 系统要求

- PHP >= 8.0
- ThinkPHP 8.0+
- OpenSSL PHP 扩展
- Redis PHP 扩展

## 安装

```bash
composer require yourname/think-encryption
```

## 配置

发布配置文件：

```bash
php think encryption:publish
```

或手动创建 `config/encrypt.php`：

```php
<?php

return [
    // AES 对称加密配置
    'aes' => [
        'cipher' => 'AES-256-CBC',      // 加密算法
        'key_length' => 32,              // 密钥长度（字节）
        'iv_length' => 16,                // IV 长度（字节）
    ],
    
    // RSA 非对称加密配置
    'rsa' => [
        'key_bits' => 2048,              // RSA 密钥位数（2048/4096）
        'key_dir' => root_path() . 'runtime/keys',
        'private_key_file' => 'rsa_private.pem',
        'public_key_file' => 'rsa_public.pem',
        'sign_algorithm' => 'SHA256',    // 签名算法
    ],
    
    // 混合加密配置
    'hybrid' => [
        'key_ttl' => 86400,               // 客户端密钥 TTL（秒）
        'rsa_rotation_period' => 86400,   // RSA 轮换周期
        'rsa_transition_period' => 3600,   // 过渡期时长
        'rsa_keep_versions' => 2,           // 保留历史版本数
        'cache_prefix' => 'hybrid_enc:',
        'version_prefix' => 'rsa_version:',
        'client_id_header' => 'X-Client-ID',
        'auto_rotate' => false,            // 是否自动轮换
    ],
    
    // 响应状态码
    'response_codes' => [
        'need_key_exchange' => 426,       // 需要密钥交换
        'need_reexchange' => 449,          // 需要重新交换
    ],
];
```

## 使用方法

### 1. 门面类（快速使用）

```php
use ThinkEncryption\EncryptionService;

// 加密数据（自动使用 AES）
$encrypted = EncryptionService::encrypt($clientId, ['foo' => 'bar']);

// 解密数据
$data = EncryptionService::decrypt($clientId, $encryptedData);

// 获取当前 RSA 版本
$version = EncryptionService::version();

// 检查客户端密钥状态
$status = EncryptionService::check($clientId);

// 清除客户端密钥
EncryptionService::clear($clientId);

// 直接使用 AES
$aes = EncryptionService::aes();
$encrypted = $aes->encrypt('data', 'your-32-char-key-here!!!!');
```

### 2. 混合加密服务

```php
use ThinkEncryption\service\encrypt\HybridEncryption;

$hybrid = new HybridEncryption();

// 获取公钥信息（发送给客户端）
$keyInfo = $hybrid->getPublicKeyInfo();
// 返回: ['public_key' => '...', 'version' => '...']

// 接收并存储客户端的 AES 密钥
$result = $hybrid->receiveAndStoreKeys(
    $clientId,
    $encryptedAesKey,   // 客户端用公钥加密的 AES 密钥
    $encryptedIv,       // 客户端用公钥加密的 IV
    $rsaVersion         // 使用的 RSA 版本
);

// 加密数据给客户端
$encrypted = $hybrid->encryptForClient($clientId, $data);

// 解密来自客户端的数据
$decrypted = $hybrid->decryptFromClient($clientId, $encryptedData);

// 强制轮换 RSA 密钥
$hybrid->rotateKeys();

// 检查客户端密钥状态
$status = $hybrid->checkClientKeyVersion($clientId);
```

### 3. 独立使用 AES/RSA

```php
use ThinkEncryption\service\encrypt\AES;
use ThinkEncryption\service\encrypt\RSA;

// AES 加密
$aes = new AES();
$encrypted = $aes->encrypt('Hello World', 'your-32-char-key-here!!!!');
$decrypted = $aes->decrypt($encrypted, 'your-32-char-key-here!!!!');

// RSA 加密（适用于小数据，如加密 AES 密钥）
$rsa = new RSA('/path/to/keys', 2048);
$rsa->generateKeyPair();
$publicKey = $rsa->getPublicKey();
$privateKey = $rsa->getPrivateKey();

// 加密/解密（自动处理分块）
$encrypted = $rsa->encrypt($largeData);
$decrypted = $rsa->decrypt($encrypted);
```

### 4. 中间件

注册中间件 `app/middleware.php`：

```php
return [
    // ...
    \ThinkEncryption\middleware\EncryptionMiddleware::class,
];
```

### 5. 内置控制器

配置路由 `route/app.php`：

```php
use think\facade\Route;

// 获取 RSA 公钥
Route::get('api/encryption/public-key', 'ThinkEncryption\controller\Encryption@publicKey');

// 交换密钥
Route::post('api/encryption/exchange-keys', 'ThinkEncryption\controller\Encryption@exchangeKeys');

// 查询加密状态
Route::get('api/encryption/status', 'ThinkEncryption\controller\Encryption@status');

// 强制轮换密钥
Route::post('api/encryption/force-rotate', 'ThinkEncryption\controller\Encryption@forceRotate');
```

## API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/encryption/public-key` | GET | 获取 RSA 公钥 |
| `/api/encryption/exchange-keys` | POST | 交换 AES 密钥 |
| `/api/encryption/status` | GET | 查询加密状态 |
| `/api/encryption/force-rotate` | POST | 强制轮换密钥 |

## 异常代码

| 代码 | 含义 | HTTP 状态码 |
|------|------|-------------|
| 1001 | 密钥未找到 | 426 |
| 1002 | 密钥已过期 | 426 |
| 2001 | 解密失败 | 400 |
| 2002 | AES 错误 | 400 |
| 3001 | RSA 错误 | 500 |
| 3002 | AES 密钥无效 | 500 |
| 4001 | 版本无效 | 449 |
| 4002 | 版本过期 | 449 |
| 5001 | 交换失败 | 400 |
| 6001 | 缺少 Client-ID | 400 |

## 运行测试

```bash
# 运行所有测试
./vendor/bin/phpunit

# 运行测试并显示详细信息
./vendor/bin/phpunit --testdox

# 运行特定测试文件
./vendor/bin/phpunit tests/service/AESTest.php
```

## 目录结构

```
think-encryption/
├── composer.json
├── phpunit.xml
├── config/
│   └── encrypt.php              # 配置文件
├── src/
│   ├── EncryptionService.php    # 门面类
│   ├── controller/
│   │   └── Encryption.php        # API 控制器
│   ├── exception/
│   │   └── EncryptException.php  # 异常类
│   ├── middleware/
│   │   └── EncryptionMiddleware.php  # 中间件
│   ├── service/
│   │   └── encrypt/
│   │       ├── AES.php           # AES 加密服务
│   │       ├── HybridEncryption.php  # 混合加密服务
│   │       └── RSA.php           # RSA 加密服务
│   └── traits/
│       └── ClientIdentity.php    # 客户端身份 Trait
├── tests/                        # 单元测试
│   ├── bootstrap.php
│   ├── TestCaseBase.php
│   ├── mocks/
│   ├── exception/
│   └── service/
└── public/
    └── static/
        ├── encryption.js         # 前端 SDK
        └── example.html           # 使用示例
```

## 安全说明

1. **AES 密钥长度**：必须 >= 32 字符（256位），短密钥会自动哈希处理
2. **RSA 密钥位数**：生产环境建议使用 4096 位
3. **密钥轮换**：建议设置合理的过渡期，确保客户端平滑切换
4. **传输安全**：公钥通过 HTTPS 传输，防止中间人攻击

## License

MIT
