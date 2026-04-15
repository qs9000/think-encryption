<?php

declare(strict_types=1);

namespace ThinkEncryption\service\encrypt;

use ThinkEncryption\exception\EncryptException;

class RSA
{
    private string $privateKeyPath;
    private string $publicKeyPath;
    private ?string $privateKey = null;
    private ?string $publicKey = null;
    private int $keyBits = 2048;

    public function __construct(?string $keyDir = null, int $keyBits = 2048)
    {
        $this->keyBits = $keyBits;
        $this->privateKeyPath = $keyDir ?? root_path() . 'runtime/keys/rsa_private.pem';
        $this->publicKeyPath = $keyDir ?? root_path() . 'runtime/keys/rsa_public.pem';

        if (is_dir($this->privateKeyPath)) {
            $this->privateKeyPath = rtrim($this->privateKeyPath, '/\\') . '/rsa_private.pem';
            $this->publicKeyPath = rtrim($this->publicKeyPath, '/\\') . '/rsa_public.pem';
        }
    }

    /**
     * 生成RSA密钥对
     * @param int $bits 密钥长度，默认2048位
     * @return array 包含私钥和公钥的数组
     * @throws EncryptException
     */
    public function generateKeyPair(int $bits = 2048): array
    {
        $config = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($config);
        if ($res === false) {
            throw EncryptException::rsaError('生成密钥对失败: ' . openssl_error_string());
        }

        if (!openssl_pkey_export($res, $privateKey)) {
            throw EncryptException::rsaError('导出私钥失败: ' . openssl_error_string());
        }

        $keyDetails = openssl_pkey_get_details($res);
        if ($keyDetails === false) {
            throw EncryptException::rsaError('获取公钥详情失败');
        }
        $publicKey = $keyDetails['key'];
        $this->keyBits = $keyDetails['bits'] ?? $bits;

        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;

        return [
            'private_key' => $privateKey,
            'public_key' => $publicKey,
        ];
    }

    /**
     * 保存密钥到文件
     * @throws EncryptException
     */
    public function saveKeys(?string $privateKeyPath = null, ?string $publicKeyPath = null): array
    {
        $privateKeyPath = $privateKeyPath ?? $this->privateKeyPath;
        $publicKeyPath = $publicKeyPath ?? $this->publicKeyPath;

        $privateDir = dirname($privateKeyPath);
        $publicDir = dirname($publicKeyPath);

        if (!is_dir($privateDir) && !mkdir($privateDir, 0755, true)) {
            throw EncryptException::rsaError("创建目录失败: {$privateDir}");
        }

        if ($publicDir !== $privateDir && !is_dir($publicDir) && !mkdir($publicDir, 0755, true)) {
            throw EncryptException::rsaError("创建目录失败: {$publicDir}");
        }

        $privateKey = $this->privateKey ?? $this->loadPrivateKey();
        $publicKey = $this->publicKey ?? $this->loadPublicKey();

        if (empty($privateKey)) {
            throw EncryptException::rsaError('私钥为空，请先生成或加载密钥');
        }
        if (empty($publicKey)) {
            throw EncryptException::rsaError('公钥为空，请先生成或加载密钥');
        }

        if (file_put_contents($privateKeyPath, $privateKey) === false) {
            throw EncryptException::rsaError("保存私钥失败: {$privateKeyPath}");
        }
        chmod($privateKeyPath, 0600);

        if (file_put_contents($publicKeyPath, $publicKey) === false) {
            throw EncryptException::rsaError("保存公钥失败: {$publicKeyPath}");
        }
        chmod($publicKeyPath, 0644);

        return [
            'private_key_path' => $privateKeyPath,
            'public_key_path' => $publicKeyPath,
        ];
    }

    /**
     * 从文件加载密钥
     * @throws EncryptException
     */
    public function loadKeys(?string $privateKeyPath = null, ?string $publicKeyPath = null): array
    {
        $privateKeyPath = $privateKeyPath ?? $this->privateKeyPath;
        $publicKeyPath = $publicKeyPath ?? $this->publicKeyPath;

        $result = [
            'private_key_loaded' => false,
            'public_key_loaded' => false,
        ];

        if (file_exists($privateKeyPath)) {
            $privateKeyContent = file_get_contents($privateKeyPath);
            if ($privateKeyContent !== false && $this->validatePrivateKey($privateKeyContent)) {
                $this->privateKey = $privateKeyContent;
                $result['private_key_loaded'] = true;
                $this->keyBits = $this->getKeyBitsFromContent($privateKeyContent) ?? $this->keyBits;
            }
        }

        if (file_exists($publicKeyPath)) {
            $publicKeyContent = file_get_contents($publicKeyPath);
            if ($publicKeyContent !== false && $this->validatePublicKey($publicKeyContent)) {
                $this->publicKey = $publicKeyContent;
                $result['public_key_loaded'] = true;
            }
        }

        return $result;
    }

    /**
     * 验证私钥格式
     */
    private function validatePrivateKey(string $key): bool
    {
        $keyResource = openssl_pkey_get_private($key);
        if ($keyResource === false) {
            throw EncryptException::rsaError('私钥格式无效');
        }
        return true;
    }

    /**
     * 验证公钥格式
     */
    private function validatePublicKey(string $key): bool
    {
        $keyResource = openssl_pkey_get_public($key);
        if ($keyResource === false) {
            throw EncryptException::rsaError('公钥格式无效');
        }
        return true;
    }

    /**
     * 从密钥内容获取密钥位数
     */
    private function getKeyBitsFromContent(string $key): ?int
    {
        return $this->getKeyBits($key);
    }

    /**
     * 获取密钥位数
     * @param string|null $key 密钥内容，如果为 null 则返回当前实例的 keyBits
     * @return int
     */
    public function getKeyBits(?string $key = null): int
    {
        if ($key !== null) {
            $keyResource = openssl_pkey_get_private($key);
            if ($keyResource === false) {
                $keyResource = openssl_pkey_get_public($key);
            }
            if ($keyResource !== false) {
                $details = openssl_pkey_get_details($keyResource);
                return $details['bits'] ?? $this->keyBits;
            }
        }
        return $this->keyBits;
    }

    /**
     * 使用公钥加密数据
     * @throws EncryptException
     */
    public function encrypt(string $data, ?string $publicKey = null): string
    {
        try {
            $key = $publicKey ?? $this->publicKey ?? $this->loadPublicKey();

            if (empty($key)) {
                throw EncryptException::rsaError('公钥为空，请提供公钥或先加载密钥');
            }

            $keyBits = $this->getKeyBits($key);
            $encrypted = '';
            // PKCS1_PADDING 下，最大可加密字节数 = (keyBits / 8) - 11
            $chunkSize = (int) floor(($keyBits / 8) - 11);

            foreach (str_split($data, $chunkSize) as $chunk) {
                $encryptedChunk = '';
                if (!openssl_public_encrypt($chunk, $encryptedChunk, $key, OPENSSL_PKCS1_PADDING)) {
                    throw EncryptException::encryptFailed('RSA加密失败: ' . openssl_error_string());
                }
                $encrypted .= $encryptedChunk;
            }

            return base64_encode($encrypted);
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw EncryptException::encryptFailed($e->getMessage(), $e);
        }
    }

    /**
     * 使用私钥解密数据
     * @throws EncryptException
     */
    public function decrypt(string $encryptedData, ?string $privateKey = null): string
    {
        try {
            $key = $privateKey ?? $this->privateKey ?? $this->loadPrivateKey();

            if (empty($key)) {
                throw EncryptException::rsaError('私钥为空，请提供私钥或先加载密钥');
            }

            $keyBits = $this->getKeyBits($key);
            $data = base64_decode($encryptedData, true);
            if ($data === false) {
                throw EncryptException::decryptFailed('Base64解码失败');
            }

            $decrypted = '';
            // RSA 解密后每个块固定为 keyBits / 8 字节
            $chunkSize = (int) ($keyBits / 8);

            foreach (str_split($data, $chunkSize) as $chunk) {
                $decryptedChunk = '';
                if (!openssl_private_decrypt($chunk, $decryptedChunk, $key, OPENSSL_PKCS1_PADDING)) {
                    throw EncryptException::decryptFailed('RSA解密失败: ' . openssl_error_string());
                }
                $decrypted .= $decryptedChunk;
            }

            return $decrypted;
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw EncryptException::decryptFailed($e->getMessage(), $e);
        }
    }

    /**
     * 使用私钥签名数据
     * @throws EncryptException
     */
    public function sign(string $data, ?string $privateKey = null, string $algorithm = 'SHA256'): string
    {
        try {
            $key = $privateKey ?? $this->privateKey ?? $this->loadPrivateKey();

            if (empty($key)) {
                throw EncryptException::rsaError('私钥为空，请提供私钥或先加载密钥');
            }

            $signature = '';
            if (!openssl_sign($data, $signature, $key, $algorithm)) {
                throw EncryptException::rsaError('签名失败: ' . openssl_error_string());
            }

            return base64_encode($signature);
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw EncryptException::rsaError($e->getMessage(), $e);
        }
    }

    /**
     * 使用公钥验证签名
     * @throws EncryptException
     */
    public function verify(string $data, string $signature, ?string $publicKey = null, string $algorithm = 'SHA256'): bool
    {
        try {
            $key = $publicKey ?? $this->publicKey ?? $this->loadPublicKey();

            if (empty($key)) {
                throw EncryptException::rsaError('公钥为空，请提供公钥或先加载密钥');
            }

            $sig = base64_decode($signature, true);
            if ($sig === false) {
                throw EncryptException::rsaError('签名Base64解码失败');
            }

            $result = openssl_verify($data, $sig, $key, $algorithm);
            if ($result === -1) {
                throw EncryptException::rsaError('验证签名失败: ' . openssl_error_string());
            }

            return $result === 1;
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw EncryptException::rsaError($e->getMessage(), $e);
        }
    }

    /**
     * 加载私钥
     * @return string|null
     */
    private function loadPrivateKey(): ?string
    {
        if ($this->privateKey !== null) {
            return $this->privateKey;
        }

        if (file_exists($this->privateKeyPath)) {
            $this->privateKey = file_get_contents($this->privateKeyPath);
            return $this->privateKey;
        }

        return null;
    }

    /**
     * 加载公钥
     * @return string|null
     */
    private function loadPublicKey(): ?string
    {
        if ($this->publicKey !== null) {
            return $this->publicKey;
        }

        if (file_exists($this->publicKeyPath)) {
            $this->publicKey = file_get_contents($this->publicKeyPath);
            return $this->publicKey;
        }

        return null;
    }

    /**
     * 获取当前加载的公钥
     * @return string|null
     */
    public function getPublicKey(): ?string
    {
        return $this->publicKey ?? $this->loadPublicKey();
    }

    /**
     * 获取当前加载的私钥
     * @return string|null
     */
    public function getPrivateKey(): ?string
    {
        return $this->privateKey ?? $this->loadPrivateKey();
    }

    /**
     * 设置私钥
     * @param string $privateKey
     */
    public function setPrivateKey(string $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    /**
     * 设置公钥
     * @param string $publicKey
     */
    public function setPublicKey(string $publicKey): void
    {
        $this->publicKey = $publicKey;
    }

    /**
     * 检查密钥文件是否存在
     * @return array
     */
    public function keyExists(): array
    {
        return [
            'private_key_exists' => file_exists($this->privateKeyPath),
            'public_key_exists' => file_exists($this->publicKeyPath),
            'private_key_path' => $this->privateKeyPath,
            'public_key_path' => $this->publicKeyPath,
        ];
    }
}
