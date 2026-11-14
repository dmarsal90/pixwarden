<?php

declare(strict_types=1);

namespace Pixwarden;

enum ImageFormat: string
{
    case Jpeg = 'jpeg';
    case Png = 'png';
    case Gif = 'gif';
    case Webp = 'webp';
    case Svg = 'svg';
    case Unknown = 'unknown';
}
