<?php

declare(strict_types=1);

namespace Pixwarden;

enum ErrorCode: string
{
    case InvalidOptions = 'invalid_options';
    case ResourceLimitExceeded = 'resource_limit_exceeded';
    case SvgRejected = 'svg_rejected';
    case CapabilityUnavailable = 'capability_unavailable';
}
