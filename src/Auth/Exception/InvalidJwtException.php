<?php

declare(strict_types=1);

namespace Azimo\Apple\Auth\Exception;

use InvalidArgumentException;

final class InvalidJwtException extends InvalidArgumentException implements AppleExceptionInterface
{
}
