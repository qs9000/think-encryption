# 快速开始

## 1. 安装插件

插件已配置为本地路径安装，已自动完成。

## 2. 使用插件

### 在控制器中使用

```php
<?php
namespace app\controller;

use app\BaseController;
use ThinkEncryption\EncryptionService;
use ThinkEncryption\exception\EncryptException;

class Test extends BaseController
{
    public function index()
    {
        try {
            $clientId = request()->header('X-Client-ID');

            // 解密请求数据
            $encryptedData = input('post.encrypted_data');
            $data = EncryptionService::decrypt($clientId, $encryptedData);

            // 处理业务逻辑...
            $result = ['message' => 'Success', 'data' => $data];

            // 加密响应数据
            $encrypted = EncryptionService::encrypt($clientId, $result);

            return json(['code' => 200, 'data' => ['encrypted_data' => $encrypted]]);

        } catch (EncryptException $e) {
            return json($e->toArray(), $e->getHttpCode());
        }
    }
}
```

### 路由配置

```php
// route/app.php

// 使用插件提供的控制器
Route::group('api/encryption', function () {
    Route::get('public-key', 'ThinkEncryption\controller\Encryption@publicKey');
    Route::post('exchange-keys', 'ThinkEncryption\controller\Encryption@exchangeKeys');
    Route::get('status', 'ThinkEncryption\controller\Encryption@status');
});

// 你的业务路由
Route::post('api/test', 'Test@index');
```

### 中间件配置

```php
// app/middleware.php

return [
    // ... 其他中间件
    \ThinkEncryption\middleware\EncryptionMiddleware::class,
];
```

### 前端使用

```html
<script src="/static/encryption.js"></script>
<script>
const client = new HybridEncryptionClient('http://localhost:8000');

async function init() {
    // 交换密钥
    await client.exchangeKeys();

    // 发送加密请求
    const result = await client.request('/api/test', {
        method: 'POST',
        body: { test: 'data' }
    });

    console.log(result);
}

init();
</script>
```

## 3. 文件复制

将插件的静态文件复制到 public 目录：

```bash
cp extend/think-encryption/public/static/encryption.js public/static/
cp extend/think-encryption/public/static/example.html public/static/
```

## 4. API 测试

获取公钥：
```bash
curl http://localhost:8000/api/encryption/public-key
```

查看状态：
```bash
curl -H "X-Client-ID: test-client" http://localhost:8000/api/encryption/status
```

## 5. 目录结构

```
extend/think-encryption/
├── composer.json          # 插件配置
├── README.md              # 完整文档
├── QUICKSTART.md          # 本文件
├── config/
│   └── encrypt.php        # 配置文件
├── src/
│   ├── EncryptionService.php    # 门面类
│   ├── controller/
│   │   └── Encryption.php       # 控制器
│   ├── exception/
│   │   └── EncryptException.php # 异常类
│   ├── middleware/
│   │   └── EncryptionMiddleware.php # 中间件
│   └── service/
│       └── encrypt/
│           ├── AES.php
│           ├── HybridEncryption.php
│           └── RSA.php
└── public/
    └── static/
        ├── encryption.js   # 前端JS
        └── example.html    # 示例页面
```
