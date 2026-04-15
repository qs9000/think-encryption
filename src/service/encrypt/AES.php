<?php

declare(strict_types=1);

namespace ThinkEncryption\service\encrypt;

use ThinkEncryption\exception\EncryptException;

class AES
{
    private const HMAC_LENGTH = 32; // SHA256 HMAC length
    private const CIPHER = 'AES-256-CBC';

    private ?string $derivedEncryptKey = null;
    private ?string $derivedHmacKey = null;
    private ?string $lastSecret = null;

    /**
     * 加密数据（带 HMAC 认证）
     * @param mixed $data 需要加密的数据
     * @param string|null $secret 加密密钥，如果为空则从环境变量 ENCRYPTION_KEY 获取
     * @param string|null $iv 加密向量，如果为空则随机生成
     * @param bool $useHmac 是否使用 HMAC 认证（默认 true）
     * @return string 加密后的数据，经过Base64编码
     * @throws EncryptException
     */
    public function encrypt(mixed $data, ?string $secret = null, ?string $iv = null, bool $useHmac = true): string
    {
        try {
            $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($json === false) {
                throw EncryptException::encryptFailed('JSON 编码失败: ' . json_last_error_msg());
            }

            $secret = $secret ?? env('ENCRYPTION_KEY');
            if ($secret === null || $secret === '' || strlen($secret) < 16) {
                throw EncryptException::aesError('加密密钥未设置或长度不足（至少16字符）');
            }

            [$encryptKey, $hmacKey] = $this->deriveKeys($secret);

            $ivLength = openssl_cipher_iv_length(self::CIPHER);

            if ($iv === null) {
                $iv = random_bytes($ivLength);
            } elseif (strlen($iv) !== $ivLength) {
                throw EncryptException::aesError("IV长度错误，需要{$ivLength}字节");
            }

            $encrypted = openssl_encrypt($json, self::CIPHER, $encryptKey, OPENSSL_RAW_DATA, $iv);
            if ($encrypted === false) {
                throw EncryptException::encryptFailed(openssl_error_string() ?: 'AES加密失败');
            }

            // HMAC 认证：计算密文 + IV 的 HMAC
            $hmac = '';
            if ($useHmac) {
                $hmac = hash_hmac('sha256', $iv . $encrypted, $hmacKey, true);
            }

            return base64_encode($iv . $encrypted . $hmac);
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw EncryptException::encryptFailed($e->getMessage(), $e);
        }
    }

    /**
     * 解密数据（验证 HMAC 认证）
     * @param string $encryptedData 加密后的数据
     * @param string|null $secret 解密密钥，如果为空则从环境变量 ENCRYPTION_KEY 获取
     * @param string|null $providedIv 解密向量，如果为空则从加密数据中提取
     * @param bool $verifyHmac 是否验证 HMAC（默认 true）
     * @return mixed 解密后的原始数据
     * @throws EncryptException
     */
    public function decrypt(string $encryptedData, ?string $secret = null, ?string $providedIv = null, bool $verifyHmac = true): mixed
    {
        try {
            if (empty($encryptedData)) {
                throw EncryptException::decryptFailed('加密数据不能为空');
            }

            $decodedData = base64_decode($encryptedData, true);
            if ($decodedData === false) {
                throw EncryptException::decryptFailed('Base64解码失败，数据格式错误');
            }

            $secret = $secret ?? env('ENCRYPTION_KEY');
            if ($secret === null || $secret === '' || strlen($secret) < 16) {
                throw EncryptException::aesError('解密密钥未设置或长度不足（至少16字符）');
            }

            [$encryptKey, $hmacKey] = $this->deriveKeys($secret);

            $ivLength = openssl_cipher_iv_length(self::CIPHER);
            $iv = $providedIv;
            $cipherText = '';

            // 如果提供了 IV，使用它；否则从数据中提取
            if ($iv !== null) {
                if (strlen($iv) !== $ivLength) {
                    throw EncryptException::aesError("IV长度错误，需要{$ivLength}字节");
                }
                $cipherText = $decodedData;
                $actualHmacLength = 0; // 使用外部 IV 时不验证 HMAC
            } else {
                // 从数据中提取 IV、密文和 HMAC
                $actualHmacLength = self::HMAC_LENGTH;

                if (strlen($decodedData) < $ivLength + $actualHmacLength) {
                    if (strlen($decodedData) >= $ivLength) {
                        $actualHmacLength = 0;
                    } else {
                        throw EncryptException::decryptFailed('加密数据格式错误，数据长度不足');
                    }
                }

                $iv = substr($decodedData, 0, $ivLength);
                $cipherText = substr($decodedData, $ivLength, strlen($decodedData) - $ivLength - $actualHmacLength);

                // 验证 HMAC
                if ($actualHmacLength > 0 && $verifyHmac) {
                    $providedHmac = substr($decodedData, strlen($decodedData) - $actualHmacLength);
                    $expectedHmac = hash_hmac('sha256', $iv . $cipherText, $hmacKey, true);
                    if (!hash_equals($expectedHmac, $providedHmac)) {
                        throw EncryptException::decryptFailed('HMAC 验证失败，数据可能被篡改');
                    }
                }
            }

            if (strlen($cipherText) % 16 !== 0) {
                throw EncryptException::decryptFailed('密文长度不是16字节的倍数');
            }

            $decrypted = openssl_decrypt($cipherText, self::CIPHER, $encryptKey, OPENSSL_RAW_DATA, $iv);
            if ($decrypted === false) {
                throw EncryptException::decryptFailed(openssl_error_string() ?: 'AES解密失败');
            }

            $data = json_decode($decrypted, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $debugMode = (bool) env('APP_DEBUG', 'false');
                $errorMsg = $debugMode ? 'JSON解码失败: ' . json_last_error_msg() : '数据解密失败：数据格式错误';
                throw EncryptException::decryptFailed($errorMsg);
            }

            return $data;
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw EncryptException::decryptFailed($e->getMessage(), $e);
        }
    }

    /**
     * 从主密钥派生加密密钥和 HMAC 密钥（带缓存）
     * @param string $secret 主密钥
     * @return array [encryptKey, hmacKey]
     */
    private function deriveKeys(string $secret): array
    {
        // 缓存检查：相同密钥直接返回缓存结果
        if ($this->lastSecret === $secret && $this->derivedEncryptKey !== null) {
            return [$this->derivedEncryptKey, $this->derivedHmacKey];
        }

        // 使用 HKDF 进行密钥派生（RFC 5869）
        $salt = 'ThinkEncryption_v1';
        
        // 派生加密密钥
        $encryptKey = hash_hkdf('sha256', $secret, 32, 'encrypt', $salt);
        
        // 派生 HMAC 密钥
        $hmacKey = hash_hkdf('sha256', $secret, 32, 'hmac', $salt);

        // 缓存结果
        $this->lastSecret = $secret;
        $this->derivedEncryptKey = $encryptKey;
        $this->derivedHmacKey = $hmacKey;
        
        return [$encryptKey, $hmacKey];
    }
}
