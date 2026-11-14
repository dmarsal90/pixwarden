<?php

declare(strict_types=1);

namespace Pixwarden;

enum Verdict: string
{
    case Allow = 'allow';
    case Sanitize = 'sanitize';
    case Reject = 'reject';
    case Review = 'review';
}
