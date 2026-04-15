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

    public function publicKey()
    {
        try {
            $keyInfo = $this->hybridEncryption->getPublicKeyInfo();
            return json([
                'code' => 200,
                'message' => 'success',
                'data' => [
                    'version' => $keyInfo['version'],
                    'public_key' => $keyInfo['public_key'],
                    'key_bits' => $keyInfo['key_bits'],
                    'previous_version' => $keyInfo['previous_version'] ?? null,
                    'transition_end_at' => $keyInfo['transition_end_at'] ?? null,
                ],
            ]);
        } catch (EncryptException $e) {
            return json($e->toArray(), $e->getHttpCode());
        } catch (\Exception $e) {
            $exception = new EncryptException(
                '获取公钥失败: ' . $e->getMessage(),
                500,
                [],
                $e
            );
            return json($exception->toArray(), 500);
        }
    }

    public function exchangeKeys(Request $request)
    {
        try {
            $clientId = $this->getClientIdOrFail($request);
            $encryptedAesKey = $request->post('encrypted_aes_key');
            $encryptedIv = $request->post('encrypted_iv');
            $rsaVersion = $request->post('rsa_version');
            if (!$encryptedAesKey || !$encryptedIv || !$rsaVersion) {
                throw EncryptException::exchangeFailed('缺少必要参数: encrypted_aes_key, encrypted_iv, rsa_version');
            }
            $result = $this->hybridEncryption->receiveAndStoreKeys(
                $clientId,
                $encryptedAesKey,
                $encryptedIv,
                $rsaVersion
            );
            return json([
                'code' => 200,
                'message' => '密钥交换成功',
                'data' => $result,
            ]);
        } catch (EncryptException $e) {
            return json($e->toArray(), $e->getHttpCode());
        } catch (\Exception $e) {
            $exception = new EncryptException(
                '密钥交换失败: ' . $e->getMessage(),
                500,
                [],
                $e
            );
            return json($exception->toArray(), 500);
        }
    }

    public function status(Request $request)
    {
        try {
            $clientId = $this->getClientIdOrFail($request);
            $keyStatus = $this->hybridEncryption->checkClientKeyVersion($clientId);
            $currentVersion = $this->hybridEncryption->getCurrentVersion();
            return json([
                'code' => 200,
                'message' => 'success',
                'data' => [
                    'client_id' => $clientId,
                    'has_encryption_key' => $keyStatus['has_key'],
                    'need_key_update' => $keyStatus['need_update'],
                    'current_rsa_version' => $currentVersion,
                    'client_rsa_version' => $keyStatus['client_version'] ?? null,
                    'is_key_valid' => $keyStatus['is_valid'] ?? false,
                ],
            ]);
        } catch (EncryptException $e) {
            return json($e->toArray(), $e->getHttpCode());
        } catch (\Exception $e) {
            $exception = new EncryptException(
                '获取状态失败: ' . $e->getMessage(),
                500,
                [],
                $e
            );
            return json($exception->toArray(), 500);
        }
    }

    public function forceRotate()
    {
        try {
            $result = $this->hybridEncryption->forceRotateKeys();
            return json([
                'code' => 200,
                'message' => '密钥轮换成功',
                'data' => $result,
            ]);
        } catch (EncryptException $e) {
            return json($e->toArray(), $e->getHttpCode());
        } catch (\Exception $e) {
            $exception = new EncryptException(
                '密钥轮换失败: ' . $e->getMessage(),
                500,
                [],
                $e
            );
            return json($exception->toArray(), 500);
        }
    }
}
