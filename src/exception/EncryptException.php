<?php

declare(strict_types=1);

namespace ThinkEncryption\exception;

use Exception;
use Throwable;

/**
 * 加密异常类
 * 用于统一处理加密、解密过程中的错误
 */
class EncryptException extends Exception
{
    // 错误代码常量
    public const CODE_KEY_NOT_FOUND = 1001;
    public const CODE_KEY_EXPIRED = 1002;
    public const CODE_KEY_INVALID = 1003;
    public const CODE_DECRYPT_FAILED = 2001;
    public const CODE_ENCRYPT_FAILED = 2002;
    public const CODE_RSA_ERROR = 3001;
    public const CODE_AES_ERROR = 3002;
    public const CODE_VERSION_INVALID = 4001;
    public const CODE_VERSION_EXPIRED = 4002;
    public const CODE_EXCHANGE_FAILED = 5001;
    public const CODE_CLIENT_ID_MISSING = 6001;

    /**
     * 错误消息映射
     */
    protected static array $messages = [
        self::CODE_KEY_NOT_FOUND => '加密密钥未找到',
        self::CODE_KEY_EXPIRED => '加密密钥已过期',
        self::CODE_KEY_INVALID => '加密密钥无效',
        self::CODE_DECRYPT_FAILED => '数据解密失败',
        self::CODE_ENCRYPT_FAILED => '数据加密失败',
        self::CODE_RSA_ERROR => 'RSA操作失败',
        self::CODE_AES_ERROR => 'AES操作失败',
        self::CODE_VERSION_INVALID => 'RSA版本无效',
        self::CODE_VERSION_EXPIRED => 'RSA版本已过期',
        self::CODE_EXCHANGE_FAILED => '密钥交换失败',
        self::CODE_CLIENT_ID_MISSING => '缺少客户端ID',
    ];

    /**
     * HTTP状态码映射
     */
    protected static array $httpCodes = [
        self::CODE_KEY_NOT_FOUND => 426,
        self::CODE_KEY_EXPIRED => 426,
        self::CODE_KEY_INVALID => 426,
        self::CODE_DECRYPT_FAILED => 400,
        self::CODE_ENCRYPT_FAILED => 500,
        self::CODE_RSA_ERROR => 500,
        self::CODE_AES_ERROR => 500,
        self::CODE_VERSION_INVALID => 449,
        self::CODE_VERSION_EXPIRED => 449,
        self::CODE_EXCHANGE_FAILED => 400,
        self::CODE_CLIENT_ID_MISSING => 400,
    ];

    /**
     * 附加数据
     */
    protected array $data = [];

    /**
     * 构造函数
     * @param string|int $message 错误消息或错误代码
     * @param int $code 错误代码
     * @param array $data 附加数据
     * @param Throwable|null $previous 上一个异常
     */
    public function __construct(
        string|int $message = '',
        int $code = 0,
        array $data = [],
        ?Throwable $previous = null
    ) {
        // 如果传入的是数字，视为错误代码
        if (is_int($message) && isset(self::$messages[$message])) {
            $code = $message;
            $message = self::$messages[$message];
        }

        // 如果code为0，尝试从消息推断
        if ($code === 0 && is_string($message)) {
            $code = $this->inferCodeFromMessage($message);
        }

        $this->data = $data;

        parent::__construct($message, $code, $previous);
    }

    /**
     * 从消息推断错误代码
     */
    protected function inferCodeFromMessage(string $message): int
    {
        foreach (self::$messages as $code => $msg) {
            if (str_contains($message, $msg) || str_contains($message, strtolower($msg))) {
                return $code;
            }
        }

        return 500;
    }

    /**
     * 获取HTTP状态码
     */
    public function getHttpCode(): int
    {
        return self::$httpCodes[$this->code] ?? 500;
    }

    /**
     * 获取附加数据
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * 设置附加数据
     */
    public function setData(array $data): self
    {
        $this->data = $data;
        return $this;
    }

    /**
     * 转换为数组格式
     */
    public function toArray(): array
    {
        return [
            'code' => $this->code,
            'message' => $this->message,
            'data' => $this->data,
        ];
    }

    /**
     * 快速创建异常
     */
    public static function keyNotFound(string $clientId, ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_KEY_NOT_FOUND,
            self::CODE_KEY_NOT_FOUND,
            ['client_id' => $clientId],
            $previous
        );
    }

    public static function keyExpired(string $clientId, ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_KEY_EXPIRED,
            self::CODE_KEY_EXPIRED,
            ['client_id' => $clientId],
            $previous
        );
    }

    public static function decryptFailed(string $reason = '', ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_DECRYPT_FAILED . ($reason ? ': ' . $reason : ''),
            self::CODE_DECRYPT_FAILED,
            [],
            $previous
        );
    }

    public static function encryptFailed(string $reason = '', ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_ENCRYPT_FAILED . ($reason ? ': ' . $reason : ''),
            self::CODE_ENCRYPT_FAILED,
            [],
            $previous
        );
    }

    public static function rsaError(string $reason = '', ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_RSA_ERROR . ($reason ? ': ' . $reason : ''),
            self::CODE_RSA_ERROR,
            [],
            $previous
        );
    }

    public static function aesError(string $reason = '', ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_AES_ERROR . ($reason ? ': ' . $reason : ''),
            self::CODE_AES_ERROR,
            [],
            $previous
        );
    }

    public static function versionInvalid(string $version, ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_VERSION_INVALID,
            self::CODE_VERSION_INVALID,
            ['version' => $version],
            $previous
        );
    }

    public static function versionExpired(string $version, ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_VERSION_EXPIRED,
            self::CODE_VERSION_EXPIRED,
            ['version' => $version],
            $previous
        );
    }

    public static function exchangeFailed(string $reason = '', ?Throwable $previous = null): self
    {
        return new self(
            self::CODE_EXCHANGE_FAILED . ($reason ? ': ' . $reason : ''),
            self::CODE_EXCHANGE_FAILED,
            [],
            $previous
        );
    }

    public static function clientIdMissing(): self
    {
        return new self(self::CODE_CLIENT_ID_MISSING, self::CODE_CLIENT_ID_MISSING);
    }
}
