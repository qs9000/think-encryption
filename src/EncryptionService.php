<?php

declare(strict_types=1);

namespace ThinkEncryption;

use ThinkEncryption\service\encrypt\HybridEncryption;
use ThinkEncryption\service\encrypt\RSA;
use ThinkEncryption\service\encrypt\AES;

/**
 * 加密服务门面类
 */
class EncryptionService
{
    private static ?HybridEncryption $hybrid = null;
    private static ?RSA $rsa = null;
    private static ?AES $aes = null;

    /**
     * 获取混合加密服务
     */
    public static function hybrid(): HybridEncryption
    {
        if (self::$hybrid === null) {
            self::$hybrid = new HybridEncryption();
        }
        return self::$hybrid;
    }

    /**
     * 获取RSA服务
     */
    public static function rsa(?string $keyDir = null): RSA
    {
        if (self::$rsa === null) {
            self::$rsa = new RSA($keyDir);
        }
        return self::$rsa;
    }

    /**
     * 获取AES服务
     */
    public static function aes(): AES
    {
        if (self::$aes === null) {
            self::$aes = new AES();
        }
        return self::$aes;
    }

    /**
     * 加密数据（为指定客户端）
     */
    public static function encrypt(string $clientId, mixed $data): string
    {
        return self::hybrid()->encryptForClient($clientId, $data);
    }

    /**
     * 解密数据（来自指定客户端）
     */
    public static function decrypt(string $clientId, string $encryptedData): mixed
    {
        return self::hybrid()->decryptFromClient($clientId, $encryptedData);
    }

    /**
     * 获取当前RSA版本
     */
    public static function version(): string
    {
        return self::hybrid()->getCurrentVersion();
    }

    /**
     * 检查客户端密钥状态
     */
    public static function check(string $clientId): array
    {
        return self::hybrid()->checkClientKeyVersion($clientId);
    }

    /**
     * 清除客户端密钥
     */
    public static function clear(string $clientId): bool
    {
        return self::hybrid()->removeClientKeys($clientId);
    }
}
