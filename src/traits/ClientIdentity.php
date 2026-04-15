<?php

declare(strict_types=1);

namespace ThinkEncryption\traits;

use think\Request;
use ThinkEncryption\exception\EncryptException;

/**
 * 客户端身份识别 Trait
 */
trait ClientIdentity
{
    // ClientId 格式：字母数字下划线，长度 4-64
    protected static string $clientIdPattern = '/^[a-zA-Z0-9_-]{4,64}$/';
    protected static string $defaultClientIdHeader = 'X-Client-ID';

    /**
     * 获取客户端 ID
     */
    protected function getClientId(?Request $request = null): ?string
    {
        $request ??= app('request');
        $clientId = $request->header($this->getClientIdHeader());

        if ($clientId && $this->validateClientId($clientId)) {
            return $clientId;
        }

        return null;
    }

    /**
     * 获取客户端 ID，不存在则抛出异常
     * @throws EncryptException
     */
    protected function getClientIdOrFail(?Request $request = null): string
    {
        $clientId = $this->getClientId($request);
        if (!$clientId) {
            throw EncryptException::clientIdMissing();
        }
        return $clientId;
    }

    /**
     * 验证 ClientId 格式
     */
    protected function validateClientId(string $clientId): bool
    {
        return preg_match(self::$clientIdPattern, $clientId) === 1;
    }

    /**
     * 获取客户端 ID header 名称
     */
    protected function getClientIdHeader(): string
    {
        return config('encrypt.hybrid.client_id_header', self::$defaultClientIdHeader);
    }
}
