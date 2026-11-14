<?php

declare(strict_types=1);

namespace Pixwarden;

use RuntimeException;
use Throwable;

class PixwardenException extends RuntimeException
{
    public function __construct(
        public readonly ErrorCode $errorCode,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
