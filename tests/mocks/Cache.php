<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\mocks;

/**
 * Cache Facade 模拟（内存存储）
 */
class Cache
{
    private static array $store = [];

    public static function get(string $name, $default = null)
    {
        if (isset(self::$store[$name])) {
            $item = self::$store[$name];
            // 检查是否过期
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
        self::$store[$name] = [
            'value' => $value,
            'expire' => $expire,
        ];
        return true;
    }

    public static function delete(string $name): bool
    {
        unset(self::$store[$name]);
        return true;
    }

    public static function has(string $name): bool
    {
        if (!isset(self::$store[$name])) {
            return false;
        }
        $item = self::$store[$name];
        if ($item['expire'] !== 0 && $item['expire'] < time()) {
            unset(self::$store[$name]);
            return false;
        }
        return true;
    }

    /**
     * 尝试添加缓存（仅当键不存在时成功）
     */
    public static function add(string $name, $value, $ttl = 0): bool
    {
        if (self::has($name)) {
            return false;
        }
        return self::set($name, $value, $ttl);
    }

    /**
     * 自增
     */
    public static function inc(string $name, int $step = 1): int|false
    {
        $value = (int) self::get($name, 0);
        $value += $step;
        self::set($name, $value);
        return $value;
    }

    /**
     * 自减
     */
    public static function dec(string $name, int $step = 1): int|false
    {
        $value = (int) self::get($name, 0);
        $value -= $step;
        self::set($name, $value);
        return $value;
    }

    /**
     * 清空所有缓存
     */
    public static function clear(): bool
    {
        self::$store = [];
        return true;
    }

    /**
     * 获取存储的键列表（调试用）
     */
    public static function getKeys(): array
    {
        return array_keys(self::$store);
    }

    /**
     * 重置存储（测试用）
     */
    public static function reset(): void
    {
        self::$store = [];
    }
}
