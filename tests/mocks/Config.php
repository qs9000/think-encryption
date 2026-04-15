<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\mocks;

/**
 * Mock Config Facade for Testing
 */
class Config
{
    private static array $config = [];

    public static function get(string $name, $default = null)
    {
        $keys = explode('.', $name);
        $value = self::$config;

        foreach ($keys as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return $default;
            }
            $value = $value[$key];
        }

        return $value;
    }

    public static function set(string $name, $value): void
    {
        $keys = explode('.', $name);
        $config = &self::$config;

        foreach ($keys as $key) {
            if (!isset($config[$key]) || !is_array($config[$key])) {
                $config[$key] = [];
            }
            $config = &$config[$key];
        }

        $config = $value;
    }

    public static function has(string $name): bool
    {
        $keys = explode('.', $name);
        $value = self::$config;

        foreach ($keys as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return false;
            }
            $value = $value[$key];
        }

        return true;
    }

    public static function reset(): void
    {
        self::$config = [];
    }
}
