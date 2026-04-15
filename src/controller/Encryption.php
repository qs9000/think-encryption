<?php

declare(strict_types=1);

namespace ThinkEncryption\controller;

use think\BaseController;
use ThinkEncryption\exception\EncryptException;
use ThinkEncryption\service\encrypt\HybridEncryption;
use ThinkEncryption\traits\ClientIdentity;
use think\facade\Config;
use think\Request;

class Encryption extends BaseController
{
    use ClientIdentity;

    private HybridEncryption $hybridEncryption;

    public function __construct()
    {
        $this->hybridEncryption = new HybridEncryption();
    }

    public function publicKey(): array
    {
        try {
            $keyInfo = $this->hybridEncryption->getPublicKeyInfo();
            return [
                'code' => 200,
                'message' => 'success',
                'data' => [
                    'version' => $keyInfo['version'],
                    'public_key' => $keyInfo['public_key'],
                    'key_bits' => $keyInfo['key_bits'],
                    'previous_version' => $keyInfo['previous_version'] ?? null,
                    'transition_end_at' => $keyInfo['transition_end_at'] ?? null,
                ],
            ];
        } catch (EncryptException $e) {
            return $this->errorResponse($e);
        }
    }

    public function exchangeKeys(Request $request): array
    {
        try {
            $clientId = $this->getClientIdOrFail($request);
            $encryptedAesKey = $request->post('encrypted_aes_key');
            $encryptedIv = $request->post('encrypted_iv');
            $rsaVersion = $request->post('rsa_version');

            if (!$encryptedAesKey || !$encryptedIv || !$rsaVersion) {
                throw EncryptException::exchangeFailed('缺少必要参数: encrypted_aes_key, encrypted_iv, rsa_version');
            }

            return [
                'code' => 200,
                'message' => '密钥交换成功',
                'data' => $this->hybridEncryption->receiveAndStoreKeys($clientId, $encryptedAesKey, $encryptedIv, $rsaVersion),
            ];
        } catch (EncryptException $e) {
            return $this->errorResponse($e);
        }
    }

    public function status(Request $request): array
    {
        try {
            $clientId = $this->getClientIdOrFail($request);
            $keyStatus = $this->hybridEncryption->checkClientKeyVersion($clientId);

            return [
                'code' => 200,
                'message' => 'success',
                'data' => [
                    'client_id' => $clientId,
                    'has_encryption_key' => $keyStatus['has_key'],
                    'need_key_update' => $keyStatus['need_update'],
                    'current_rsa_version' => $this->hybridEncryption->getCurrentVersion(),
                    'client_rsa_version' => $keyStatus['client_version'] ?? null,
                    'is_key_valid' => $keyStatus['is_valid'] ?? false,
                ],
            ];
        } catch (EncryptException $e) {
            return $this->errorResponse($e);
        }
    }

    public function forceRotate(Request $request): array
    {
        $adminToken = $request->header('X-Admin-Token');
        $expectedToken = env('ENCRYPTION_ADMIN_TOKEN');

        if (empty($expectedToken)) {
            return ['code' => 500, 'message' => '管理员认证未配置'];
        }

        if (empty($adminToken) || !hash_equals($expectedToken, $adminToken)) {
            return ['code' => 403, 'message' => '无权执行此操作'];
        }

        try {
            return [
                'code' => 200,
                'message' => '密钥轮换成功',
                'data' => $this->hybridEncryption->forceRotateKeys(),
            ];
        } catch (EncryptException $e) {
            return $this->errorResponse($e);
        }
    }

    /**
     * 安全错误响应（非调试模式隐藏详情）
     */
    protected function errorResponse(EncryptException $e): array
    {
        $response = $e->toArray();
        if (!Config::get('app.app_debug', false)) {
            $response['message'] = '操作失败，请稍后重试';
        }
        return $response;
    }
}
