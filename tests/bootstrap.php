<?php

declare(strict_types=1);

/**
 * 测试引导文件
 * 模拟 ThinkPHP 框架的核心功能
 */

// 定义项目根路径
if (!defined('ROOT_PATH')) {
    define('ROOT_PATH', dirname(__DIR__) . '/');
}

// 创建 root_path() 函数（ThinkPHP 框架兼容）
if (!function_exists('root_path')) {
    function root_path(): string
    {
        return ROOT_PATH;
    }
}

// 模拟 env() 函数
if (!function_exists('env')) {
    function env(string $name, $default = null)
    {
        static $env = [];

        if (empty($env)) {
            // 从 .env 文件加载（如果存在）
            $envFile = ROOT_PATH . '.env';
            if (file_exists($envFile)) {
                $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($lines as $line) {
                    if (strpos($line, '#') === 0) {
                        continue;
                    }
                    if (strpos($line, '=') !== false) {
                        [$key, $value] = explode('=', $line, 2);
                        $env[trim($key)] = trim($value);
                    }
                }
            }
        }

        // 优先使用 getenv (putenv)，其次使用 .env 文件
        $getenvValue = getenv($name);
        if ($getenvValue !== false) {
            return $getenvValue;
        }

        return $env[$name] ?? $default;
    }
}

// 模拟 app() 函数
if (!function_exists('app')) {
    $appContainer = [];

    function app(string $name = null)
    {
        global $appContainer;

        if ($name === null) {
            return $appContainer;
        }

        if ($name === 'request') {
            if (!isset($appContainer['request'])) {
                $appContainer['request'] = new class {
                    public function header(string $name = null, $default = null)
                    {
                        $headers = $this->getHeaders();
                        if ($name === null) {
                            return $headers;
                        }
                        return $headers[$name] ?? $default;
                    }

                    public function getHeaders(): array
                    {
                        $headers = [];
                        foreach ($_SERVER as $key => $value) {
                            if (strpos($key, 'HTTP_') === 0) {
                                $header = str_replace('_', '-', substr($key, 5));
                                $header = ucwords(strtolower($header), '-');
                                $headers[$header] = $value;
                            }
                        }
                        return $headers;
                    }

                    public function pathinfo(): string
                    {
                        return $_SERVER['REQUEST_URI'] ?? '/';
                    }
                };
            }
            return $appContainer['request'];
        }

        return $appContainer[$name] ?? null;
    }
}

// 模拟 Config facade
if (!class_exists('think\facade\Config')) {
    class_alias(\ThinkEncryption\tests\mocks\Config::class, 'think\facade\Config');
}

// 模拟 Cache facade
if (!class_exists('think\facade\Cache')) {
    class_alias(\ThinkEncryption\tests\mocks\Cache::class, 'think\facade\Cache');
}

// 创建缓存目录
$cacheDir = sys_get_temp_dir() . '/think-encryption-test-cache';
if (!is_dir($cacheDir)) {
    mkdir($cacheDir, 0755, true);
}
