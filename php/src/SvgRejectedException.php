<?php

declare(strict_types=1);

namespace Pixwarden;

final class SvgRejectedException extends PixwardenException
{
    public function __construct(string $message)
    {
        parent::__construct(ErrorCode::SvgRejected, $message);
    }
}
