<?php

declare(strict_types=1);

namespace Azimo\Apple\Tests\Unit\Auth\Factory;

use Azimo\Apple\Auth\Factory\AppleJwtStructFactory;
use Azimo\Apple\Auth\Struct\JwtPayload;
use Lcobucci\JWT\Token;
use DateTimeImmutable;

final class AppleJwtStructFactoryTest extends \Mockery\Adapter\Phpunit\MockeryTestCase
{
    private AppleJwtStructFactory $appleJwtStructFactory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->appleJwtStructFactory = new AppleJwtStructFactory();
    }

    public function testIfCreateJwtPayloadFromTokenReturnsExpectedJsonPayload(): void
    {
        $date = new DateTimeImmutable();

        $this->assertEquals(
            new JwtPayload(
                'https://appleid.apple.com',
                ['com.acme.app'],
                $date,
                $date,
                'foo.bar.baz',
                'qGzMhtsfTCom-bl1PJYLHk',
                'foo@privaterelay.appleid.com',
                true,
                true,
                1591622011,
                true
            ),
            $this->appleJwtStructFactory->createJwtPayloadFromToken(
                new Token\Plain(
                    new Token\DataSet([
                        'kid' => 'eXaunmL',
                        'alg' => 'RS256',
                    ], ''),
                    new Token\DataSet([
                        'iss' => 'https://appleid.apple.com',
                        'aud' => ['com.acme.app'],
                        'exp' => $date,
                        'iat' => $date,
                        'sub' => 'foo.bar.baz',
                        'c_hash' => 'qGzMhtsfTCom-bl1PJYLHk',
                        'email' => 'foo@privaterelay.appleid.com',
                        'email_verified' => 'true',
                        'is_private_email' => 'true',
                        'auth_time' => 1591622011,
                        'nonce_supported' => true,
                    ], ''),
                    Token\Signature::fromEmptyData(),
                )
            )
        );
    }
}
