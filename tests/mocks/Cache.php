<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\mocks;

/**
 * Mock Cache Facade for Testing
 */
class Cache
{
    private static array $cache = [];

    public static function get(string $name, $default = null)
    {
        if (isset(self::$cache[$name])) {
            $item = self::$cache[$name];
            // 检查是否过期
            if (isset($item['expire_at']) && $item['expire_at'] < time()) {
                unset(self::$cache[$name]);
                return $default;
            }
            return $item['value'];
        }

        return $default;
    }

    public static function set(string $name, $value, ?int $ttl = null): bool
    {
        self::$cache[$name] = [
            'value' => $value,
            'expire_at' => $ttl !== null ? time() + $ttl : null,
        ];

        return true;
    }

    public static function has(string $name): bool
    {
        if (!isset(self::$cache[$name])) {
            return false;
        }

        $item = self::$cache[$name];
        if (isset($item['expire_at']) && $item['expire_at'] < time()) {
            unset(self::$cache[$name]);
            return false;
        }

        return true;
    }

    public static function delete(string $name): bool
    {
        unset(self::$cache[$name]);
        return true;
    }

    public static function clear(): bool
    {
        self::$cache = [];
        return true;
    }

    /**
     * 模拟 add 操作（仅当 key 不存在时设置）
     */
    public static function add(string $name, $value, int $ttl = 0): bool
    {
        if (self::has($name)) {
            return false;
        }

        return self::set($name, $value, $ttl ?: null);
    }

    /**
     * 模拟 pull 操作（获取并删除）
     */
    public static function pull(string $name, $default = null)
    {
        $value = self::get($name, $default);
        self::delete($name);
        return $value;
    }

    public static function reset(): void
    {
        self::$cache = [];
    }
}
