<?php

declare(strict_types=1);

namespace ThinkEncryption\middleware;

use ThinkEncryption\exception\EncryptException;
use ThinkEncryption\service\encrypt\HybridEncryption;
use ThinkEncryption\traits\ClientIdentity;

class EncryptionMiddleware
{
    use ClientIdentity;

    private HybridEncryption $hybridEncryption;
    private static ?array $normalizedExcludePaths = null;
    private static ?string $configHash = null;

    public function __construct()
    {
        $this->hybridEncryption = new HybridEncryption();
    }

    /**
     * 获取规范化的排除路径（带配置哈希检查的静态缓存）
     */
    private function getNormalizedExcludePaths(): array
    {
        $excludePaths = config('encrypt.middleware.exclude_paths', [
            '/api/encryption/public-key',
            '/api/encryption/exchange-keys',
            '/api/encryption/status',
        ]);
        $currentHash = md5(json_encode($excludePaths));
        
        // 配置变化时清除缓存
        if (self::$configHash !== $currentHash) {
            self::$normalizedExcludePaths = null;
            self::$configHash = $currentHash;
        }
        
        if (self::$normalizedExcludePaths === null) {
            // 规范化路径：统一添加前缀 '/' 并移除末尾斜杠
            self::$normalizedExcludePaths = array_map(function ($p) {
                return '/' . trim(ltrim($p, '/'), '/');
            }, $excludePaths);
        }
        return self::$normalizedExcludePaths;
    }

    public function handle($request, \Closure $next)
    {
        try {
            $path = '/' . ltrim($request->pathinfo(), '/');
            if (in_array($path, $this->getNormalizedExcludePaths())) {
                return $next($request);
            }
            $clientId = $this->getClientIdOrFail($request);
            $keyStatus = $this->hybridEncryption->checkClientKeyVersion($clientId);
            if (!$keyStatus['has_key']) {
                throw EncryptException::keyNotFound($clientId);
            }
            if (!$keyStatus['is_valid']) {
                throw new EncryptException(
                    EncryptException::CODE_VERSION_EXPIRED,
                    EncryptException::CODE_VERSION_EXPIRED,
                    [
                        'client_id' => $clientId,
                        'current_version' => $keyStatus['current_version'],
                        'client_version' => $keyStatus['client_version'],
                    ]
                );
            }
            if ($keyStatus['need_update']) {
                $response = $next($request);
                if (is_object($response) && method_exists($response, 'header')) {
                    $response->header('X-Key-Update-Required', 'true');
                    $response->header('X-Current-Key-Version', $keyStatus['current_version']);
                }
                return $response;
            }
            return $next($request);
        } catch (EncryptException $e) {
            return json($e->toArray(), $e->getHttpCode());
        } catch (\Exception $e) {
            $encryptException = new EncryptException(
                $e->getMessage(),
                500,
                [],
                $e
            );
            return json($encryptException->toArray(), 500);
        }
    }
}
