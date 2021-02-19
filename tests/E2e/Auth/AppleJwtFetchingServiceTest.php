<?php

declare(strict_types=1);

namespace Azimo\Apple\Tests\E2e\Auth;

use Azimo\Apple\Auth\Service\AppleJwtFetchingService;
use Azimo\Apple\Auth\Struct\JwtPayload;
use Mockery\Adapter\Phpunit\MockeryTestCase;

final class AppleJwtFetchingServiceTest extends MockeryTestCase
{
    private AppleJwtFetchingService $appleJwtFetchingService;

    public function setUp(): void
    {
        parent::setUp();

        $this->appleJwtFetchingService = new AppleJwtFetchingService(
            'https://appleid.apple.com',
            'com.c.azimo.stage',
            'https://appleid.apple.com'
        );
    }

    public function testIfGetJwtPayloadReturnExpectedJwtPayload(): void
    {
        $jwtPayload = $this->appleJwtFetchingService->getJwtPayload(
            'eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmMuYXppbW8uc3RhZ2UiLCJleHAiOjE2MTMyMTIzNjIsImlhdCI6MTYxMzEyNTk2Miwic3ViIjoiMDAwNTYwLjE4MDM2YjI3MmI5MjRkYTg5ZWY3N2RjNDYyNDhkODRhLjA3MjEiLCJjX2hhc2giOiJ4SGpPV24zblpUa3JTS1dRSGRRZmFBIiwiYXV0aF90aW1lIjoxNjEzMTI1OTYyLCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.YShVEmo-QGDnMxU_M9wkwOFcqC5vqvMvXDDlZvQ1VO-WA74_CYOBMbdMKvvTWWGgpvnykNVduvixuFkv_3vpRo2llydwllmVJtMxshTx-kIDmBnInP03lP2jdaDSonDmm0UiXtGEmOqqeFiT_sgUn5o0jfUUreNrXMBM9eLpzEDcjyMW_u3qBhds2SQlsJew6Hd9w16lMTngrJYrMq2H6gogWaCqoXdXexJGdQYfBiX2J14XEgGAyW_7ZupFKT0YCb_OwBQubocsdKbRiw7KlHZVH4vcCaz6e5as9Z-g9V8o4eOFMhuYaugmuGdpBruulyOgDgdPYmR3JCMdPeLFdA'
        );

        self::assertInstanceOf(JwtPayload::class, $jwtPayload);
    }
}
