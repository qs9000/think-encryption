<?php

declare(strict_types=1);

namespace ThinkEncryption\service\encrypt;

use ThinkEncryption\exception\EncryptException;
use think\facade\Cache;
use think\facade\Config;

class HybridEncryption
{
    private array $config;
    private RSA $rsa;
    private AES $aes;
    private ?string $cacheEncryptionKey = null;

    // 缓存
    private ?int $rotationCheckTimestamp = null;
    private ?string $rotationCheckResult = null;
    private ?string $currentVersionCache = null;

    public function __construct()
    {
        $this->config = Config::get('encrypt');
        $this->rsa = new RSA($this->config['rsa']['key_dir'], $this->config['rsa']['key_bits'] ?? 3072);
        $this->aes = new AES();
        $this->initCacheEncryptionKey();
    }

    /**
     * 清除内部缓存
     */
    public function clearCache(): void
    {
        $this->currentVersionCache = null;
        $this->rotationCheckTimestamp = null;
        $this->rotationCheckResult = null;
    }

    /**
     * 初始化缓存加密密钥
     * 使用服务端主密钥派生出用于加密客户端密钥的密钥
     */
    private function initCacheEncryptionKey(): void
    {
        if (!($this->config['hybrid']['client_key_encryption'] ?? true)) {
            return;
        }

        $masterKey = env('ENCRYPTION_KEY') ?: env('APP_KEY');
        if (empty($masterKey)) {
            throw EncryptException::aesError('缓存加密需要配置 ENCRYPTION_KEY 或 APP_KEY 环境变量');
        }

        // 使用 HKDF 派生出缓存加密密钥
        $this->cacheEncryptionKey = hash_hkdf('sha256', $masterKey, 32, 'client_key_storage', 'ThinkEncryption_v1');
    }

    /**
     * 加密客户端密钥数据
     */
    private function encryptClientKeyData(array $keyData): string
    {
        if ($this->cacheEncryptionKey === null) {
            return json_encode($keyData, JSON_UNESCAPED_UNICODE);
        }

        return $this->aes->encrypt($keyData, $this->cacheEncryptionKey, null, true);
    }

    /**
     * 解密客户端密钥数据
     */
    private function decryptClientKeyData(string $encryptedData): array
    {
        if ($this->cacheEncryptionKey === null) {
            return json_decode($encryptedData, true);
        }

        return $this->aes->decrypt($encryptedData, $this->cacheEncryptionKey, null, true);
    }

    /**
     * 获取当前RSA版本（带内存缓存）
     * @throws EncryptException
     */
    public function getCurrentVersion(): string
    {
        try {
            // 优先返回内存缓存
            if ($this->currentVersionCache !== null) {
                return $this->currentVersionCache;
            }

            $versionKey = $this->config['hybrid']['version_prefix'] . 'current';
            $version = Cache::get($versionKey);
            if (!$version) {
                $version = $this->initializeKeys();
            }
            
            $this->currentVersionCache = $version;
            return $version;
        } catch (\Exception $e) {
            throw EncryptException::rsaError('获取当前版本失败: ' . $e->getMessage(), $e);
        }
    }

    /**
     * 初始化RSA密钥对
     * @throws EncryptException
     */
    public function initializeKeys(): string
    {
        try {
            $keyDir = $this->config['rsa']['key_dir'];
            $version = date('YmdHis');
            $this->rsa->generateKeyPair($this->config['rsa']['key_bits']);
            $privateKeyFile = "{$keyDir}/rsa_private_{$version}.pem";
            $publicKeyFile = "{$keyDir}/rsa_public_{$version}.pem";
            $this->rsa->saveKeys($privateKeyFile, $publicKeyFile);
            $this->rsa->saveKeys(
                "{$keyDir}/{$this->config['rsa']['private_key_file']}",
                "{$keyDir}/{$this->config['rsa']['public_key_file']}"
            );
            $versionKey = $this->config['hybrid']['version_prefix'] . 'current';
            $versionInfo = [
                'version' => $version,
                'created_at' => time(),
                'private_key' => $privateKeyFile,
                'public_key' => $publicKeyFile,
            ];
            Cache::set($versionKey, $version, $this->config['hybrid']['rsa_rotation_period'] * 2);
            Cache::set($this->config['hybrid']['version_prefix'] . $version, $versionInfo, $this->config['hybrid']['rsa_rotation_period'] * 2);
            $this->cleanupOldVersions();
            
            // 清除版本缓存，确保下次获取返回最新版本
            $this->currentVersionCache = $version;
            
            return $version;
        } catch (\Exception $e) {
            throw EncryptException::rsaError('初始化密钥失败: ' . $e->getMessage(), $e);
        }
    }

    /**
     * 检查并轮换密钥（带缓存）
     * @throws EncryptException
     */
    public function checkAndRotateKeys(): ?string
    {
        try {
            if (!$this->config['hybrid']['auto_rotate']) {
                return null;
            }

            // 缓存检查：5秒内不重复检查
            $now = time();
            if ($this->rotationCheckResult !== null && 
                $this->rotationCheckTimestamp !== null && 
                ($now - $this->rotationCheckTimestamp) < 5) {
                return $this->rotationCheckResult;
            }

            $versionKey = $this->config['hybrid']['version_prefix'] . 'current';
            $currentVersion = Cache::get($versionKey);
            if (!$currentVersion) {
                $this->rotationCheckResult = $this->initializeKeys();
                $this->rotationCheckTimestamp = $now;
                return $this->rotationCheckResult;
            }
            $versionInfo = Cache::get($this->config['hybrid']['version_prefix'] . $currentVersion);
            if (!$versionInfo) {
                $this->rotationCheckResult = $this->initializeKeys();
                $this->rotationCheckTimestamp = $now;
                return $this->rotationCheckResult;
            }
            $createdAt = $versionInfo['created_at'] ?? 0;
            $rotationPeriod = $this->config['hybrid']['rsa_rotation_period'];
            if ($now - $createdAt >= $rotationPeriod) {
                $this->rotationCheckResult = $this->rotateKeys();
            } else {
                $this->rotationCheckResult = null;
            }
            $this->rotationCheckTimestamp = $now;
            return $this->rotationCheckResult;
        } catch (\Exception $e) {
            throw EncryptException::rsaError('检查密钥轮换失败: ' . $e->getMessage(), $e);
        }
    }

    /**
     * 执行密钥轮换
     * @throws EncryptException
     */
    private function rotateKeys(): string
    {
        $lockKey = $this->config['hybrid']['version_prefix'] . 'rotate_lock';
        $lockTtl = $this->config['hybrid']['rotate_lock_ttl'] ?? 120; // 默认 120 秒

        // 尝试获取锁，防止并发轮换
        if (!Cache::add($lockKey, time(), $lockTtl)) {
            // 已有其他进程在轮换，等待并返回当前版本
            usleep(100000); // 等待 100ms
            return $this->getCurrentVersion();
        }

        try {
            $keyDir = $this->config['rsa']['key_dir'];
            $newVersion = date('YmdHis');
            $oldVersion = $this->getCurrentVersion();
            $this->rsa->generateKeyPair($this->config['rsa']['key_bits']);
            $privateKeyFile = "{$keyDir}/rsa_private_{$newVersion}.pem";
            $publicKeyFile = "{$keyDir}/rsa_public_{$newVersion}.pem";
            $this->rsa->saveKeys($privateKeyFile, $publicKeyFile);
            $this->rsa->saveKeys(
                "{$keyDir}/{$this->config['rsa']['private_key_file']}",
                "{$keyDir}/{$this->config['rsa']['public_key_file']}"
            );
            $transitionPeriod = $this->config['hybrid']['rsa_transition_period'];
            Cache::set($this->config['hybrid']['version_prefix'] . 'previous', $oldVersion, $transitionPeriod);
            $versionInfo = [
                'version' => $newVersion,
                'created_at' => time(),
                'private_key' => $privateKeyFile,
                'public_key' => $publicKeyFile,
            ];
            Cache::set($this->config['hybrid']['version_prefix'] . 'current', $newVersion, $this->config['hybrid']['rsa_rotation_period'] * 2);
            Cache::set($this->config['hybrid']['version_prefix'] . $newVersion, $versionInfo, $this->config['hybrid']['rsa_rotation_period'] * 2);
            $this->cleanupOldVersions();
            
            // 清除版本缓存，确保下次获取返回最新版本
            $this->currentVersionCache = $newVersion;
            
            return $newVersion;
        } catch (\Exception $e) {
            throw EncryptException::rsaError('密钥轮换失败: ' . $e->getMessage(), $e);
        } finally {
            Cache::delete($lockKey);
        }
    }

    /**
     * 清理旧版本密钥
     */
    private function cleanupOldVersions(): void
    {
        $keyDir = $this->config['rsa']['key_dir'];
        $keepVersions = $this->config['hybrid']['rsa_keep_versions'];
        $previousVersion = Cache::get($this->config['hybrid']['version_prefix'] . 'previous');
        $files = glob("{$keyDir}/rsa_private_*.pem");

        if (count($files) <= $keepVersions) {
            return;
        }

        usort($files, fn($a, $b) => filemtime($b) - filemtime($a));
        $filesToDelete = array_slice($files, $keepVersions);

        foreach ($filesToDelete as $file) {
            $version = str_replace(['rsa_private_', '.pem'], '', basename($file));

            // 跳过 previous 版本（过渡期内可能需要）
            if ($previousVersion !== null && $version === $previousVersion) {
                continue;
            }

            $publicKeyFile = "{$keyDir}/rsa_public_{$version}.pem";

            // 记录删除失败（而不是静默忽略）
            if (file_exists($file) && !@unlink($file)) {
                error_log("[ThinkEncryption] 清理旧版本密钥失败: {$file}");
            }
            if (file_exists($publicKeyFile) && !@unlink($publicKeyFile)) {
                error_log("[ThinkEncryption] 清理旧版本公钥失败: {$publicKeyFile}");
            }
            Cache::delete($this->config['hybrid']['version_prefix'] . $version);
        }
    }

    /**
     * 获取公钥信息
     * @throws EncryptException
     */
    public function getPublicKeyInfo(): array
    {
        try {
            $this->checkAndRotateKeys();
            $currentVersion = $this->getCurrentVersion();
            $versionInfo = Cache::get($this->config['hybrid']['version_prefix'] . $currentVersion);
            if (!$versionInfo || !file_exists($versionInfo['public_key'])) {
                throw EncryptException::rsaError('公钥文件不存在');
            }
            $publicKey = file_get_contents($versionInfo['public_key']);
            if ($publicKey === false) {
                throw EncryptException::rsaError('读取公钥文件失败');
            }
            $previousVersion = Cache::get($this->config['hybrid']['version_prefix'] . 'previous');
            $result = [
                'version' => $currentVersion,
                'public_key' => $publicKey,
                'key_bits' => $this->config['rsa']['key_bits'],
            ];
            if ($previousVersion) {
                $result['previous_version'] = $previousVersion;
                $result['transition_end_at'] = time() + $this->config['hybrid']['rsa_transition_period'];
            }
            return $result;
        } catch (\Exception $e) {
            throw EncryptException::rsaError('获取公钥信息失败: ' . $e->getMessage(), $e);
        }
    }

    /**
     * 接收并存储客户端密钥
     * @throws EncryptException
     */
    public function receiveAndStoreKeys(string $clientId, string $encryptedAesKey, string $encryptedIv, string $rsaVersion): array
    {
        try {
            $versionInfo = Cache::get($this->config['hybrid']['version_prefix'] . $rsaVersion);
            if (!$versionInfo) {
                $previousVersion = Cache::get($this->config['hybrid']['version_prefix'] . 'previous');
                if ($previousVersion && $previousVersion === $rsaVersion) {
                    $versionInfo = Cache::get($this->config['hybrid']['version_prefix'] . $previousVersion);
                }
            }
            if (!$versionInfo) {
                throw EncryptException::versionExpired($rsaVersion);
            }
            $privateKeyPath = $versionInfo['private_key'];
            $publicKeyPath = $versionInfo['public_key'];
            
            // 为每个版本创建独立的 RSA 实例，避免状态混乱
            $rsa = new RSA($this->config['rsa']['key_dir'], $this->config['rsa']['key_bits'] ?? 3072);
            $rsa->loadKeys($privateKeyPath, $publicKeyPath);
            
            $aesKey = $rsa->decrypt($encryptedAesKey);
            $iv = $rsa->decrypt($encryptedIv);
            if (strlen($aesKey) !== $this->config['aes']['key_length']) {
                throw EncryptException::exchangeFailed('AES密钥长度错误');
            }
            if (strlen($iv) !== $this->config['aes']['iv_length']) {
                throw EncryptException::exchangeFailed('IV长度错误');
            }
            $cacheKey = $this->config['hybrid']['cache_prefix'] . $clientId;
            $keyData = [
                'aes_key' => base64_encode($aesKey),
                'iv' => base64_encode($iv),
                'rsa_version' => $rsaVersion,
                'created_at' => time(),
                'last_used' => time(),
            ];
            // 加密存储客户端密钥
            $encryptedKeyData = $this->encryptClientKeyData($keyData);
            Cache::set($cacheKey, $encryptedKeyData, $this->config['hybrid']['key_ttl']);
            return [
                'success' => true,
                'client_id' => $clientId,
                'rsa_version' => $rsaVersion,
                'expires_at' => time() + $this->config['hybrid']['key_ttl'],
            ];
        } catch (\Exception $e) {
            throw EncryptException::exchangeFailed($e->getMessage(), $e);
        }
    }

    /**
     * 获取客户端密钥
     * @throws EncryptException
     */
    public function getClientKeys(string $clientId): ?array
    {
        try {
            $cacheKey = $this->config['hybrid']['cache_prefix'] . $clientId;
            $encryptedData = Cache::get($cacheKey);
            if (!$encryptedData) {
                return null;
            }
            $keyData = $this->decryptClientKeyData($encryptedData);
            if (!$keyData || !isset($keyData['aes_key'])) {
                return null;
            }
            return [
                'aes_key' => base64_decode($keyData['aes_key']),
                'iv' => base64_decode($keyData['iv']),
                'rsa_version' => $keyData['rsa_version'],
            ];
        } catch (\Exception $e) {
            throw EncryptException::keyNotFound($clientId, $e);
        }
    }

    /**
     * 刷新客户端密钥 TTL 并更新最后使用时间
     * @throws EncryptException
     */
    public function refreshClientKey(string $clientId): bool
    {
        try {
            $cacheKey = $this->config['hybrid']['cache_prefix'] . $clientId;
            $encryptedData = Cache::get($cacheKey);
            if (!$encryptedData) {
                return false;
            }
            $keyData = $this->decryptClientKeyData($encryptedData);
            if (!$keyData) {
                return false;
            }
            $keyData['last_used'] = time();
            $encryptedKeyData = $this->encryptClientKeyData($keyData);
            Cache::set($cacheKey, $encryptedKeyData, $this->config['hybrid']['key_ttl']);
            return true;
        } catch (\Exception $e) {
            throw EncryptException::keyNotFound($clientId, $e);
        }
    }

    /**
     * 续期客户端密钥 TTL（已废弃，请使用 refreshClientKey）
     * @deprecated 使用 refreshClientKey 代替
     * @throws EncryptException
     */
    public function touchClientKey(string $clientId): bool
    {
        return $this->refreshClientKey($clientId);
    }

    /**
     * 为客户端加密数据
     * @throws EncryptException
     */
    public function encryptForClient(string $clientId, mixed $data): string
    {
        $keys = $this->getClientKeys($clientId);
        if (!$keys) {
            throw EncryptException::keyNotFound($clientId);
        }
        return $this->aes->encrypt($data, $keys['aes_key'], $keys['iv']);
    }

    /**
     * 解密客户端数据
     * @throws EncryptException
     */
    public function decryptFromClient(string $clientId, string $encryptedData): mixed
    {
        $keys = $this->getClientKeys($clientId);
        if (!$keys) {
            throw EncryptException::keyNotFound($clientId);
        }
        return $this->aes->decrypt($encryptedData, $keys['aes_key'], $keys['iv']);
    }

    /**
     * 检查客户端密钥版本
     * @throws EncryptException
     */
    public function checkClientKeyVersion(string $clientId): array
    {
        try {
            $keys = $this->getClientKeys($clientId);
            $currentVersion = $this->getCurrentVersion();
            if (!$keys) {
                return [
                    'has_key' => false,
                    'need_update' => true,
                    'current_version' => $currentVersion,
                ];
            }
            $clientVersion = $keys['rsa_version'];
            $needUpdate = $clientVersion !== $currentVersion;
            $previousVersion = Cache::get($this->config['hybrid']['version_prefix'] . 'previous');
            $isValid = ($clientVersion === $currentVersion) || ($clientVersion === $previousVersion);
            return [
                'has_key' => true,
                'need_update' => $needUpdate,
                'current_version' => $currentVersion,
                'client_version' => $clientVersion,
                'is_valid' => $isValid,
            ];
        } catch (\Exception $e) {
            throw EncryptException::rsaError('检查客户端密钥版本失败: ' . $e->getMessage(), $e);
        }
    }

    /**
     * 移除客户端密钥
     */
    public function removeClientKeys(string $clientId): bool
    {
        $cacheKey = $this->config['hybrid']['cache_prefix'] . $clientId;
        return Cache::delete($cacheKey);
    }

    /**
     * 强制轮换密钥
     * @throws EncryptException
     */
    public function forceRotateKeys(): array
    {
        try {
            $oldVersion = $this->getCurrentVersion();
            $newVersion = $this->rotateKeys();
            return [
                'success' => true,
                'old_version' => $oldVersion,
                'new_version' => $newVersion,
                'message' => '密钥轮换成功，客户端需要在过渡期内重新交换密钥',
            ];
        } catch (\Exception $e) {
            throw EncryptException::rsaError('强制轮换密钥失败: ' . $e->getMessage(), $e);
        }
    }
}
