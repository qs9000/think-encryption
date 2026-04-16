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

    public static function set(string $name, $value, mixed $ttl = null, array $options = []): bool
    {
        $expireAt = null;

        // 合并 options 和 ttl 中的过期时间设置
        $mergedOptions = $options;

        // 如果 ttl 是数组，也合并进来
        if (is_array($ttl)) {
            $mergedOptions = array_merge($ttl, $options);
        }

        // 检查 NX 条件
        if (isset($mergedOptions['nx']) && self::has($name)) {
            return false; // NX: key 已存在，设置失败
        }

        // 获取过期时间
        if (isset($mergedOptions['ex'])) {
            $expireAt = time() + (int) $mergedOptions['ex'];
        } elseif (isset($mergedOptions['px'])) {
            $expireAt = time() + (int) $mergedOptions['px'] / 1000;
        } elseif ($ttl !== null && !is_array($ttl)) {
            $expireAt = time() + (int) $ttl;
        }

        self::$cache[$name] = [
            'value' => $value,
            'expire_at' => $expireAt,
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

    /**
     * 返回 handler（模拟 Redis 客户端）
     */
    public static function handler(): RedisHandler
    {
        return new RedisHandler();
    }
}

/**
 * 模拟 Redis Handler
 */
class RedisHandler
{
    private static array $cache = [];

    public function set(string $key, $value, ...$args): bool
    {
        $nx = false;
        $ex = null;

        foreach ($args as $i => $arg) {
            if (strtoupper($arg) === 'NX') {
                $nx = true;
            } elseif (strtoupper($arg) === 'EX' && isset($args[$i + 1])) {
                $ex = (int) $args[$i + 1];
            }
        }

        // NX 条件：key 已存在则失败
        if ($nx && isset(self::$cache[$key])) {
            $item = self::$cache[$key];
            if (!isset($item['expire_at']) || $item['expire_at'] >= time()) {
                return false;
            }
        }

        self::$cache[$key] = [
            'value' => $value,
            'expire_at' => $ex !== null ? time() + $ex : null,
        ];

        return true;
    }
}
