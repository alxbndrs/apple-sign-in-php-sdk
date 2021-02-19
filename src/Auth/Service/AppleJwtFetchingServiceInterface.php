<?php

declare(strict_types=1);

namespace Azimo\Apple\Auth\Service;

use Azimo\Apple\Auth\Struct\JwtPayload;

interface AppleJwtFetchingServiceInterface
{
    public function getJwtPayload(string $jwt): JwtPayload;
}
