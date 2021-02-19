<?php

declare(strict_types=1);

namespace Azimo\Apple\Tests\Unit\Auth\Jwt;

use Azimo\Apple\APi;
use Azimo\Apple\Auth\Exception;
use Azimo\Apple\Auth\Jwt\JwtVerifier;
use Lcobucci\JWT;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryTestCase;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

final class JwtVerifierTest extends MockeryTestCase
{
    private Api\AppleApiClientInterface $appleApiClient;
    private RSA $rsaMock;
    private JWT\Token $jwtMock;
    private JwtVerifier $jwtVerifier;
    private JWT\Validator $validator;

    protected function setUp(): void
    {
        parent::setUp();

        $this->appleApiClient = Mockery::mock(Api\AppleApiClientInterface::class);
        $this->rsaMock = Mockery::mock(RSA::class);
        $this->jwtMock = Mockery::mock(JWT\Token::class);
        $this->validator = Mockery::mock(JWT\Validator::class);

        $this->jwtVerifier = new JwtVerifier($this->appleApiClient, $this->validator, $this->rsaMock, new JWT\Signer\Rsa\Sha256());
    }

    public function testIfVerifyThrowsKeysFetchingFailedExceptionWhenFailedToFetchJsonWebKeySet(): void
    {
        $this->appleApiClient->shouldReceive('getAuthKeys')
            ->once()
            ->withNoArgs()
            ->andThrow(new Api\Exception\PublicKeyFetchingFailedException('Connection error'));

        $this->expectException(Exception\KeysFetchingFailedException::class);
        $this->expectExceptionMessage('Connection error');
        $this->jwtVerifier->verify($this->jwtMock);
    }

    public function testIfVerifyThrowsInvalidCryptographicAlgorithmExceptionWhenAlgorithmIsNotSupported(): void
    {
        $this->appleApiClient->shouldReceive('getAuthKeys')
            ->once()
            ->withNoArgs()
            ->andReturn(new Api\Response\JsonWebKeySetCollection([]));

        $this->jwtMock->shouldReceive('headers')
            ->once()
            ->andReturn(new JWT\Token\DataSet(['kid' => 'foo'], ''));

        $this->expectException(Exception\InvalidCryptographicAlgorithmException::class);
        $this->expectExceptionMessage(
            'Cryptographic algorithm `foo` is not supported. Supported algorithms: `86D88Kf,eXaunmL,YuyXoY`'
        );
        $this->jwtVerifier->verify($this->jwtMock);
    }

    public function testIfVerifyThrowsInvalidCryptographicAlgorithmExceptionWhenAuthKeyNotExistForGivenAlgorithm(): void
    {
        $this->appleApiClient->shouldReceive('getAuthKeys')
            ->once()
            ->withNoArgs()
            ->andReturn(new Api\Response\JsonWebKeySetCollection([]));

        $this->jwtMock->shouldReceive('headers')
            ->once()
            ->andReturn(new JWT\Token\DataSet(['kid' => '86D88Kf'], ''));

        $this->expectException(Exception\InvalidCryptographicAlgorithmException::class);
        $this->expectExceptionMessage('Unsupported cryptographic algorithm passed `86D88Kf');
        $this->jwtVerifier->verify($this->jwtMock);
    }

    public function testIfVerifyReturnsTrueWhenTokenIsCorrect(): void
    {
        $this->appleApiClient->shouldReceive('getAuthKeys')
            ->once()
            ->withNoArgs()
            ->andReturn(
                new Api\Response\JsonWebKeySetCollection(
                    [
                        '86D88Kf' => new Api\Response\JsonWebKeySet(
                            'RSA',
                            '86D88Kf',
                            'sig',
                            'RS256',
                            'iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ',
                            'AQAB'
                        ),
                    ]
                )
            );

        $this->jwtMock->shouldReceive('headers')
            ->once()
            ->andReturn(new JWT\Token\DataSet(['kid' => '86D88Kf'], ''));

        $this->rsaMock->shouldReceive('loadKey')
            ->once()
            ->with(
                Mockery::on(
                    function (array $argument) {
                        $this->assertArrayHasKey('exponent', $argument);
                        $this->assertArrayHasKey('modulus', $argument);
                        $this->assertInstanceOf(BigInteger::class, $argument['exponent']);
                        $this->assertInstanceOf(BigInteger::class, $argument['modulus']);

                        return true;
                    }
                )
            );

        $this->validator->shouldReceive('validate')
            ->once()
            ->andReturn(true);

        $this->rsaMock->shouldReceive('getPublicKey')
            ->withNoArgs()
            ->once()
            ->andReturn('publicKey');

        self::assertTrue($this->jwtVerifier->verify($this->jwtMock));
    }

    public function testIfVerifyReturnsTrueWhenTokenIsCorrectMalformed(): void
    {
        $this->appleApiClient->shouldReceive('getAuthKeys')
            ->once()
            ->withNoArgs()
            ->andReturn(
                new Api\Response\JsonWebKeySetCollection(
                    [
                        '86D88Kf' => new Api\Response\JsonWebKeySet(
                            'RSA',
                            '86D88Kf',
                            'sig',
                            'RS256',
                            'iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ',
                            'AQAB'
                        ),
                    ]
                )
            );

        $this->jwtMock->shouldReceive('headers')
            ->once()
            ->andReturn(new JWT\Token\DataSet(['kid' => '86D88Kf'], ''));

        $this->rsaMock->shouldReceive('loadKey')
            ->once()
            ->with(
                Mockery::on(
                    function (array $argument) {
                        $this->assertArrayHasKey('exponent', $argument);
                        $this->assertArrayHasKey('modulus', $argument);
                        $this->assertInstanceOf(BigInteger::class, $argument['exponent']);
                        $this->assertInstanceOf(BigInteger::class, $argument['modulus']);

                        return true;
                    }
                )
            );

        $this->rsaMock->shouldReceive('getPublicKey')
            ->withNoArgs()
            ->once()
            ->andReturn('publicKey');

        $this->validator->shouldReceive('validate')
            ->once()
            ->andReturn(false);

        self::assertFalse($this->jwtVerifier->verify($this->jwtMock));
    }
}
