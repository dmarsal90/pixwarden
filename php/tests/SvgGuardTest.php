<?php

declare(strict_types=1);

namespace Pixwarden\Tests;

use Pixwarden\Scanner;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class SvgGuardTest extends TestCase
{
    public function testSanitizerRemovesScriptAndEventAttribute(): void
    {
        $source = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect onload="x" width="1"/></svg>';
        $result = (new Scanner())->sanitizeSvg($source);
        self::assertSame('<svg xmlns="http://www.w3.org/2000/svg"><rect width="1"></rect></svg>', $result['bytes']);
        self::assertSame(['script' => 1], $result['removedElements']);
        self::assertSame(1, $result['removedAttributes']);
        self::assertSame('passed', $result['postCheckStatus']);
    }

    public function testExternalReferencesAndDoctypeAreRejectedOrRemoved(): void
    {
        $scanner = new Scanner();
        $externalReference = '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://example.invalid/x.svg"/></svg>';
        $sanitized = $scanner->sanitizeSvg($externalReference);
        self::assertStringNotContainsString('https://', $sanitized['bytes']);
        self::assertSame(['image' => 1], $sanitized['removedElements']);

        $this->expectException(RuntimeException::class);
        $scanner->sanitizeSvg('<!DOCTYPE svg [<!ENTITY x "x">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>');
    }

    public function testUnknownLocalReferenceIsRejected(): void
    {
        $this->expectException(RuntimeException::class);
        (new Scanner())->sanitizeSvg('<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(#missing)"/></svg>');
    }
}
