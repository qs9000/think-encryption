<?php

declare(strict_types=1);

namespace ThinkEncryption\middleware;

use ThinkEncryption\exception\EncryptException;
use ThinkEncryption\service\encrypt\HybridEncryption;
use ThinkEncryption\traits\ClientIdentity;
use think\facade\Config;

class EncryptionMiddleware
{
    use ClientIdentity;

    private HybridEncryption $hybridEncryption;
    private array $config;

    public function __construct()
    {
        $this->hybridEncryption = new HybridEncryption();
        $this->config = Config::get('encrypt');
    }

    protected function getConfig(): array
    {
        return $this->config;
    }

    public function handle($request, \Closure $next)
    {
        try {
            $path = $request->pathinfo();
            $excludePaths = [
                'api/encryption/public-key',
                'api/encryption/exchange-keys',
                'api/encryption/status',
            ];
            if (in_array($path, $excludePaths)) {
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
