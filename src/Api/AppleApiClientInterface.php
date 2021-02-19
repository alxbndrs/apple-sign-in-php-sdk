<?php

declare(strict_types=1);

namespace Azimo\Apple\Api;

interface AppleApiClientInterface
{
    public function getAuthKeys(): Response\JsonWebKeySetCollection;
}
