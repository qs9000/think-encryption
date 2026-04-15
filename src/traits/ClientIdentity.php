<?php

declare(strict_types=1);

namespace ThinkEncryption\traits;

use think\Request;

/**
 * 客户端身份识别 Trait
 * 提供获取客户端 ID 的统一方法
 */
trait ClientIdentity
{
    /**
     * 获取配置
     */
    abstract protected function getConfig(): array;

    /**
     * 获取客户端 ID
     * @param Request|null $request
     * @return string|null
     */
    protected function getClientId(?Request $request = null): ?string
    {
        if ($request === null) {
            $request = app('request');
        }

        $headerName = $this->getConfig()['hybrid']['client_id_header'] ?? 'X-Client-ID';
        return $request->header($headerName) ?: null;
    }

    /**
     * 获取客户端 ID，如果不存在则抛出异常
     * @param Request|null $request
     * @return string
     * @throws \ThinkEncryption\exception\EncryptException
     */
    protected function getClientIdOrFail(?Request $request = null): string
    {
        $clientId = $this->getClientId($request);
        if (!$clientId) {
            throw \ThinkEncryption\exception\EncryptException::clientIdMissing();
        }
        return $clientId;
    }
}
