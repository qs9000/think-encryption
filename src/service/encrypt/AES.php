<?php

declare(strict_types=1);

namespace ThinkEncryption\service\encrypt;

use ThinkEncryption\exception\EncryptException;

class AES
{
    /**
     * 加密数据
     * @param mixed $data 需要加密的数据
     * @param string|null $secret 加密密钥，如果为空则从环境变量 JWT_SECRET 获取
     * @param string|null $iv 加密向量，如果为空则随机生成
     * @return string 加密后的数据，经过Base64编码
     * @throws EncryptException
     */
    public function encrypt(mixed $data, ?string $secret = null, ?string $iv = null): string
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

            if (strlen($secret) < 32) {
                $secret = hash('sha256', $secret, true);
            } else {
                $secret = substr($secret, 0, 32);
            }

            $cipher = 'AES-256-CBC';
            $ivLength = openssl_cipher_iv_length($cipher);

            if ($iv === null) {
                $iv = random_bytes($ivLength);
            } elseif (strlen($iv) !== $ivLength) {
                throw EncryptException::aesError("IV长度错误，需要{$ivLength}字节");
            }

            $encrypted = openssl_encrypt($json, $cipher, $secret, OPENSSL_RAW_DATA, $iv);
            if ($encrypted === false) {
                throw EncryptException::encryptFailed(openssl_error_string() ?: 'AES加密失败');
            }

            return base64_encode($iv . $encrypted);
        } catch (EncryptException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw EncryptException::encryptFailed($e->getMessage(), $e);
        }
    }

    /**
     * 解密数据
     * @param string $encryptedData 加密后的数据
     * @param string|null $secret 解密密钥，如果为空则从环境变量 JWT_SECRET 获取
     * @param string|null $iv 解密向量，如果为空则从加密数据中提取
     * @return mixed 解密后的原始数据
     * @throws EncryptException
     */
    public function decrypt(string $encryptedData, ?string $secret = null, ?string $iv = null): mixed
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

            if (strlen($secret) < 32) {
                $secret = hash('sha256', $secret, true);
            } else {
                $secret = substr($secret, 0, 32);
            }

            $cipher = 'AES-256-CBC';
            $ivLength = openssl_cipher_iv_length($cipher);

            if ($iv !== null) {
                if (strlen($iv) !== $ivLength) {
                    throw EncryptException::aesError("IV长度错误，需要{$ivLength}字节");
                }
                $cipherText = $decodedData;
            } else {
                if (strlen($decodedData) < $ivLength) {
                    throw EncryptException::decryptFailed('加密数据格式错误，数据长度不足');
                }
                $iv = substr($decodedData, 0, $ivLength);
                $cipherText = substr($decodedData, $ivLength);
            }

            if (strlen($cipherText) % 16 !== 0) {
                throw EncryptException::decryptFailed('密文长度不是16字节的倍数');
            }

            $decrypted = openssl_decrypt($cipherText, $cipher, $secret, OPENSSL_RAW_DATA, $iv);
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
}
