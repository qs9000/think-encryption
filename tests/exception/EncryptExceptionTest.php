<?php

declare(strict_types=1);

namespace ThinkEncryption\tests\exception;

use ThinkEncryption\exception\EncryptException;
use ThinkEncryption\tests\TestCaseBase;

class EncryptExceptionTest extends TestCaseBase
{
    public function testConstructorWithCode(): void
    {
        $exception = new EncryptException(EncryptException::CODE_KEY_NOT_FOUND);
        $this->assertEquals(EncryptException::CODE_KEY_NOT_FOUND, $exception->getCode());
        $this->assertEquals('加密密钥未找到', $exception->getMessage());
    }

    public function testConstructorWithMessage(): void
    {
        $exception = new EncryptException('自定义错误消息', 500);
        $this->assertEquals('自定义错误消息', $exception->getMessage());
        $this->assertEquals(500, $exception->getCode());
    }

    public function testGetHttpCode(): void
    {
        $exception = new EncryptException(EncryptException::CODE_KEY_NOT_FOUND);
        $this->assertEquals(426, $exception->getHttpCode());

        $exception2 = new EncryptException(EncryptException::CODE_DECRYPT_FAILED);
        $this->assertEquals(400, $exception2->getHttpCode());

        $exception3 = new EncryptException(EncryptException::CODE_RSA_ERROR);
        $this->assertEquals(500, $exception3->getHttpCode());
    }

    public function testDefaultHttpCode(): void
    {
        $exception = new EncryptException('未知错误', 9999);
        $this->assertEquals(500, $exception->getHttpCode());
    }

    public function testGetData(): void
    {
        $data = ['key' => 'value', 'number' => 42];
        $exception = new EncryptException('错误', 500, $data);
        $this->assertEquals($data, $exception->getData());
    }

    public function testSetData(): void
    {
        $exception = new EncryptException('错误');
        $newData = ['updated' => true];
        $exception->setData($newData);
        $this->assertEquals($newData, $exception->getData());
    }

    public function testToArray(): void
    {
        $exception = new EncryptException(
            '测试错误',
            500,
            ['extra' => 'data']
        );

        $array = $exception->toArray();

        $this->assertArrayHasKey('code', $array);
        $this->assertArrayHasKey('message', $array);
        $this->assertArrayHasKey('data', $array);
        $this->assertEquals(500, $array['code']);
        $this->assertEquals('测试错误', $array['message']);
        $this->assertEquals(['extra' => 'data'], $array['data']);
    }

    public function testKeyNotFoundFactory(): void
    {
        $exception = EncryptException::keyNotFound('client-123');
        $this->assertEquals(EncryptException::CODE_KEY_NOT_FOUND, $exception->getCode());
        $this->assertEquals(['client_id' => 'client-123'], $exception->getData());
    }

    public function testKeyExpiredFactory(): void
    {
        $exception = EncryptException::keyExpired('client-456');
        $this->assertEquals(EncryptException::CODE_KEY_EXPIRED, $exception->getCode());
        $this->assertEquals(['client_id' => 'client-456'], $exception->getData());
    }

    public function testDecryptFailedFactory(): void
    {
        $exception = EncryptException::decryptFailed('CRC error');
        $this->assertEquals(EncryptException::CODE_DECRYPT_FAILED, $exception->getCode());
        $this->assertStringContainsString('CRC error', $exception->getMessage());
    }

    public function testEncryptFailedFactory(): void
    {
        $exception = EncryptException::encryptFailed('Padding error');
        $this->assertEquals(EncryptException::CODE_ENCRYPT_FAILED, $exception->getCode());
        $this->assertStringContainsString('Padding error', $exception->getMessage());
    }

    public function testRsaErrorFactory(): void
    {
        $exception = EncryptException::rsaError('Key generation failed');
        $this->assertEquals(EncryptException::CODE_RSA_ERROR, $exception->getCode());
        $this->assertStringContainsString('Key generation failed', $exception->getMessage());
    }

    public function testAesErrorFactory(): void
    {
        $exception = EncryptException::aesError('Invalid IV');
        $this->assertEquals(EncryptException::CODE_AES_ERROR, $exception->getCode());
        $this->assertStringContainsString('Invalid IV', $exception->getMessage());
    }

    public function testVersionInvalidFactory(): void
    {
        $exception = EncryptException::versionInvalid('v12345');
        $this->assertEquals(EncryptException::CODE_VERSION_INVALID, $exception->getCode());
        $this->assertEquals(['version' => 'v12345'], $exception->getData());
    }

    public function testVersionExpiredFactory(): void
    {
        $exception = EncryptException::versionExpired('v99999');
        $this->assertEquals(EncryptException::CODE_VERSION_EXPIRED, $exception->getCode());
        $this->assertEquals(['version' => 'v99999'], $exception->getData());
    }

    public function testExchangeFailedFactory(): void
    {
        $exception = EncryptException::exchangeFailed('Missing parameter');
        $this->assertEquals(EncryptException::CODE_EXCHANGE_FAILED, $exception->getCode());
        $this->assertStringContainsString('Missing parameter', $exception->getMessage());
    }

    public function testClientIdMissingFactory(): void
    {
        $exception = EncryptException::clientIdMissing();
        $this->assertEquals(EncryptException::CODE_CLIENT_ID_MISSING, $exception->getCode());
        $this->assertEquals(400, $exception->getHttpCode());
    }

    public function testExceptionChaining(): void
    {
        $previous = new \RuntimeException('Original error');
        $exception = new EncryptException('Wrapped error', 500, [], $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testInferCodeFromMessage(): void
    {
        $exception = new EncryptException('加密密钥未找到', 0);

        // 应该推断出正确的代码
        $this->assertEquals(EncryptException::CODE_KEY_NOT_FOUND, $exception->getCode());
    }

    public function testAllErrorCodes(): void
    {
        $codes = [
            EncryptException::CODE_KEY_NOT_FOUND,
            EncryptException::CODE_KEY_EXPIRED,
            EncryptException::CODE_KEY_INVALID,
            EncryptException::CODE_DECRYPT_FAILED,
            EncryptException::CODE_ENCRYPT_FAILED,
            EncryptException::CODE_RSA_ERROR,
            EncryptException::CODE_AES_ERROR,
            EncryptException::CODE_VERSION_INVALID,
            EncryptException::CODE_VERSION_EXPIRED,
            EncryptException::CODE_EXCHANGE_FAILED,
            EncryptException::CODE_CLIENT_ID_MISSING,
        ];

        // 验证所有代码都是唯一的
        $this->assertEquals(count($codes), count(array_unique($codes)));

        // 验证每个代码都有对应的 HTTP 码
        foreach ($codes as $code) {
            $exception = new EncryptException($code);
            $this->assertGreaterThanOrEqual(400, $exception->getHttpCode());
            $this->assertLessThan(600, $exception->getHttpCode());
        }
    }

    public function testHttpCodesRange(): void
    {
        // 所有 HTTP 状态码应该在合理范围内
        $exception = new EncryptException(EncryptException::CODE_KEY_NOT_FOUND);
        $this->assertEquals(426, $exception->getHttpCode());

        $exception2 = new EncryptException(EncryptException::CODE_CLIENT_ID_MISSING);
        $this->assertEquals(400, $exception2->getHttpCode());

        $exception3 = new EncryptException(EncryptException::CODE_RSA_ERROR);
        $this->assertEquals(500, $exception3->getHttpCode());
    }
}
