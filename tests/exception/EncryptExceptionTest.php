<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\exception;

use ThinkEncryption\exception\EncryptException;
use PHPUnit\Framework\TestCase;

class EncryptExceptionTest extends TestCase
{
    public function testConstructorWithCode(): void
    {
        $exception = new EncryptException('Test error', 1001);
        $this->assertEquals(1001, $exception->getCode());
        $this->assertEquals('Test error', $exception->getMessage());
    }

    public function testConstructorWithMessage(): void
    {
        $exception = new EncryptException('Custom message');
        $this->assertEquals('Custom message', $exception->getMessage());
        $this->assertEquals(500, $exception->getCode());
    }

    public function testGetHttpCode(): void
    {
        $exception = new EncryptException('Error', EncryptException::CODE_KEY_NOT_FOUND);
        $this->assertEquals(426, $exception->getHttpCode());
    }

    public function testDefaultHttpCode(): void
    {
        $exception = new EncryptException('Error', 9999);
        $this->assertEquals(500, $exception->getHttpCode());
    }

    public function testGetData(): void
    {
        $data = ['key' => 'value'];
        $exception = new EncryptException('Error', 1001, $data);
        $this->assertEquals($data, $exception->getData());
    }

    public function testSetData(): void
    {
        $exception = new EncryptException('Error');
        $exception->setData(['new' => 'data']);
        $this->assertEquals(['new' => 'data'], $exception->getData());
    }

    public function testToArray(): void
    {
        $exception = new EncryptException('Test error', EncryptException::CODE_KEY_NOT_FOUND, ['client_id' => 'test']);
        $array = $exception->toArray();

        $this->assertArrayHasKey('code', $array);
        $this->assertArrayHasKey('message', $array);
        $this->assertArrayHasKey('data', $array);
        $this->assertEquals('Test error', $array['message']);
    }

    public function testKeyNotFoundFactory(): void
    {
        $exception = EncryptException::keyNotFound('client-123');
        $this->assertEquals(EncryptException::CODE_KEY_NOT_FOUND, $exception->getCode());
        $this->assertEquals(426, $exception->getHttpCode());
    }

    public function testKeyExpiredFactory(): void
    {
        $exception = EncryptException::keyExpired('client-123');
        $this->assertEquals(EncryptException::CODE_KEY_EXPIRED, $exception->getCode());
        $this->assertEquals(426, $exception->getHttpCode());
    }

    public function testDecryptFailedFactory(): void
    {
        $exception = EncryptException::decryptFailed('Invalid data');
        $this->assertEquals(EncryptException::CODE_DECRYPT_FAILED, $exception->getCode());
        $this->assertEquals(400, $exception->getHttpCode());
    }

    public function testRsaErrorFactory(): void
    {
        $exception = EncryptException::rsaError('Key generation failed');
        $this->assertEquals(EncryptException::CODE_RSA_ERROR, $exception->getCode());
        $this->assertEquals(500, $exception->getHttpCode());
    }

    public function testAesErrorFactory(): void
    {
        $exception = EncryptException::aesError('Invalid key');
        $this->assertEquals(EncryptException::CODE_AES_ERROR, $exception->getCode());
        $this->assertEquals(500, $exception->getHttpCode());
    }

    public function testClientIdMissingFactory(): void
    {
        $exception = EncryptException::clientIdMissing();
        $this->assertEquals(EncryptException::CODE_CLIENT_ID_MISSING, $exception->getCode());
        $this->assertEquals(400, $exception->getHttpCode());
    }

    public function testExceptionChaining(): void
    {
        $previous = new \RuntimeException('Previous error');
        $exception = new EncryptException('Wrapped error', 500, [], $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testAllErrorCodes(): void
    {
        $codes = [
            EncryptException::CODE_KEY_NOT_FOUND => 426,
            EncryptException::CODE_KEY_EXPIRED => 426,
            EncryptException::CODE_DECRYPT_FAILED => 400,
            EncryptException::CODE_ENCRYPT_FAILED => 500, // 服务器端错误
            EncryptException::CODE_RSA_ERROR => 500,
            EncryptException::CODE_AES_ERROR => 500,
            EncryptException::CODE_VERSION_INVALID => 449,
            EncryptException::CODE_VERSION_EXPIRED => 449,
            EncryptException::CODE_EXCHANGE_FAILED => 400,
            EncryptException::CODE_CLIENT_ID_MISSING => 400,
        ];

        foreach ($codes as $code => $expectedHttpCode) {
            $exception = new EncryptException('Test', $code);
            $this->assertEquals($expectedHttpCode, $exception->getHttpCode(), "Code {$code} should have HTTP {$expectedHttpCode}");
        }
    }
}
