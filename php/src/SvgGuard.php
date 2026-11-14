<?php

declare(strict_types=1);

namespace Pixwarden;

use DOMDocument;
use DOMElement;
use DOMNode;

/** Secure static SVG profile and allowlist serializer using PHP's XML parser. */
final class SvgGuard
{
    private const SVG_NS = 'http://www.w3.org/2000/svg';
    private const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';
    private const MAX_BYTES = 2_097_152;
    private const MAX_NODES = 50_000;
    private const MAX_DEPTH = 64;
    private const MAX_ATTRIBUTES = 100_000;
    private const MAX_OUTPUT_BYTES = 4_194_304;

    private const ELEMENTS = [
        'svg', 'g', 'path', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon',
        'text', 'tspan', 'title', 'desc', 'defs', 'linearGradient', 'radialGradient', 'stop',
        'clipPath', 'mask', 'pattern',
    ];
    private const ACTIVE = ['script', 'style', 'foreignObject', 'iframe', 'object', 'embed', 'image', 'use', 'a', 'animate', 'animateMotion', 'animateTransform', 'set', 'audio', 'video', 'filter'];
    private const ATTRIBUTES = [
        'id', 'class', 'x', 'y', 'x1', 'y1', 'x2', 'y2', 'cx', 'cy', 'r', 'rx', 'ry',
        'width', 'height', 'viewBox', 'preserveAspectRatio', 'd', 'points', 'fill', 'stroke',
        'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'stroke-miterlimit', 'fill-rule',
        'clip-rule', 'opacity', 'fill-opacity', 'stroke-opacity', 'transform', 'offset',
        'stop-color', 'stop-opacity', 'gradientUnits', 'gradientTransform', 'spreadMethod',
        'patternUnits', 'patternContentUnits', 'patternTransform', 'clipPathUnits', 'maskUnits',
        'maskContentUnits', 'font-family', 'font-size', 'font-weight', 'text-anchor',
        'dominant-baseline', 'shape-rendering', 'vector-effect',
    ];

    public static function looksLikeSvg(string $bytes): bool
    {
        $prefix = ltrim(preg_replace('/^\xEF\xBB\xBF/', '', substr($bytes, 0, 512)) ?? '');
        return str_starts_with($prefix, '<svg') || (str_starts_with($prefix, '<?xml') && str_contains($prefix, '<svg'));
    }

    /** @return array{validity: string, findings: list<array<string, mixed>>} */
    public function inspect(string $bytes, int $maxBytes): array
    {
        if (!class_exists(DOMDocument::class)) {
            return ['validity' => 'unknown', 'findings' => []];
        }
        try {
            $result = $this->parseAndSerialize($bytes, min(self::MAX_BYTES, $maxBytes));
            $findings = [];
            if ($result['removedElements'] !== []) {
                $findings[] = $this->finding(
                    $result['activeElements'] > 0 ? 'SVG-001' : 'SVG-001',
                    $result['activeElements'] > 0 ? 'Active SVG element removed' : 'Unsupported SVG element removed',
                    $result['activeElements'] > 0 ? 'The document contains an active or externally linked SVG element.' : 'One or more elements are outside the supported static SVG subset.',
                    $result['activeElements'] > 0 ? 'high' : 'medium',
                    $result['activeElements'] > 0 ? 'confirmed' : 'inconclusive',
                    $result['activeElements'] > 0 ? 'failed' : 'passed',
                );
            }
            if ($result['removedAttributes'] > 0) {
                $unsafe = $result['unsafeAttributes'] > 0;
                $findings[] = $this->finding('SVG-002', $unsafe ? 'Active SVG attribute removed' : 'Unsupported SVG attribute removed', $unsafe ? 'The document contains an event handler, active URL, or unsupported external reference.' : 'One or more attributes are outside the supported static SVG subset.', $unsafe ? 'high' : 'medium', $unsafe ? 'confirmed' : 'inconclusive', $unsafe ? 'failed' : 'passed');
            }
            return ['validity' => 'valid', 'findings' => $findings];
        } catch (\RuntimeException $error) {
            $limited = str_contains($error->getMessage(), 'limit');
            return [
                'validity' => 'invalid',
                'findings' => [$this->finding($limited ? 'SVG-005' : 'SVG-009', 'SVG could not be safely parsed', $error->getMessage(), 'high', 'confirmed', 'failed')],
            ];
        }
    }

    /** @return array<string, mixed> */
    public function sanitize(string $bytes): array
    {
        $result = $this->parseAndSerialize($bytes, self::MAX_BYTES);
        $verification = $this->parseAndSerialize($result['output'], self::MAX_BYTES);
        if ($verification['output'] !== $result['output'] || $verification['removedAttributes'] !== 0 || $verification['removedElements'] !== []) {
            throw new SanitizationFailureException('Sanitized SVG did not pass its post-sanitization check.');
        }
        return [
            'bytes' => $result['output'],
            'inputBytes' => strlen($bytes),
            'outputBytes' => strlen($result['output']),
            'removedElements' => $result['removedElements'],
            'removedAttributes' => $result['removedAttributes'],
            'postCheckStatus' => 'passed',
        ];
    }

    /** @return array<string, mixed> */
    private function parseAndSerialize(string $bytes, int $maxBytes): array
    {
        if (!class_exists(DOMDocument::class)) {
            throw new CapabilityUnavailableException('PHP ext-dom is required for SVG inspection.');
        }
        if (strlen($bytes) > $maxBytes) {
            throw new ResourceLimitExceededException('SVG input limit exceeded.');
        }
        if (preg_match('//u', $bytes) !== 1) {
            throw new SvgRejectedException('SVG input must be well-formed UTF-8.');
        }

        $source = preg_replace('/^\xEF\xBB\xBF/', '', $bytes) ?? $bytes;
        $sourceWithoutDeclaration = preg_replace('/^\s*<\?xml\s+[^?]*\?>/i', '', $source, 1) ?? $source;
        $markupForDeclarationCheck = preg_replace('/<!--.*?-->|<!\[CDATA\[.*?\]\]>/s', '', $sourceWithoutDeclaration) ?? $sourceWithoutDeclaration;
        if (stripos($markupForDeclarationCheck, '<!DOCTYPE') !== false || stripos($markupForDeclarationCheck, '<!ENTITY') !== false) {
            throw new SvgRejectedException('SVG document types and entities are not accepted.');
        }
        if (str_contains($sourceWithoutDeclaration, '<?')) {
            throw new SvgRejectedException('SVG processing instructions are not accepted.');
        }

        $document = new DOMDocument();
        $document->resolveExternals = false;
        $document->substituteEntities = false;
        $document->validateOnParse = false;
        $document->preserveWhiteSpace = true;
        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();
        try {
            $loaded = $document->loadXML($source, LIBXML_NONET | LIBXML_COMPACT);
            $errors = libxml_get_errors();
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        if (!$loaded || $errors !== [] || $document->doctype !== null || !$document->documentElement instanceof DOMElement) {
            throw new SvgRejectedException('SVG XML is not well-formed under the selected profile.');
        }
        if ($document->documentElement->localName !== 'svg' || $document->documentElement->namespaceURI !== self::SVG_NS) {
            throw new SvgRejectedException('SVG root must be one element in the SVG namespace.');
        }

        $state = [
            'output' => '', 'removedElements' => [], 'removedAttributes' => 0,
            'activeElements' => 0, 'unsafeAttributes' => 0, 'nodeCount' => 0,
            'attributeCount' => 0, 'ids' => [], 'references' => [],
        ];
        $this->serializeNode($document->documentElement, 1, false, true, $state);
        foreach ($state['references'] as $reference) {
            if (!isset($state['ids'][$reference])) {
                throw new SvgRejectedException('SVG contains a local reference to an unknown identifier.');
            }
        }
        return $state;
    }

    /** @param array<string, mixed> $state */
    private function serializeNode(DOMNode $node, int $depth, bool $blocked, bool $root, array &$state): void
    {
        if ($node instanceof DOMElement) {
            $state['nodeCount']++;
            if ($state['nodeCount'] > self::MAX_NODES) {
                throw new ResourceLimitExceededException('SVG node limit exceeded.');
            }
            if ($depth > self::MAX_DEPTH) {
                throw new ResourceLimitExceededException('SVG depth limit exceeded.');
            }
            $name = $node->localName;
            $allowed = !$blocked && $node->namespaceURI === self::SVG_NS && in_array($name, self::ELEMENTS, true);
            if (!$allowed) {
                $state['removedElements'][$name] = ($state['removedElements'][$name] ?? 0) + 1;
                if (!$blocked && in_array($name, self::ACTIVE, true)) {
                    $state['activeElements']++;
                }
            } else {
                $this->append($state, '<' . $name);
                if ($root) {
                    $this->append($state, ' xmlns="' . self::SVG_NS . '"');
                }
                foreach ($node->attributes as $attribute) {
                    $state['attributeCount']++;
                    if ($state['attributeCount'] > self::MAX_ATTRIBUTES) {
                        throw new ResourceLimitExceededException('SVG attribute limit exceeded.');
                    }
                    if ($attribute->namespaceURI === self::XMLNS_NS || $attribute->nodeName === 'xmlns' || $attribute->prefix === 'xmlns') {
                        continue;
                    }
                    $attrName = $attribute->localName ?? $attribute->nodeName;
                    $value = $attribute->value;
                    if ($attribute->namespaceURI !== null || !in_array($attrName, self::ATTRIBUTES, true) || strlen($value) > 4096) {
                        $state['removedAttributes']++;
                        if (preg_match('/^on/i', $attrName) === 1 || in_array($attrName, ['href', 'src', 'style'], true)) {
                            $state['unsafeAttributes']++;
                        }
                        continue;
                    }
                    if ($attrName === 'id') {
                        if (preg_match('/^[A-Za-z_][A-Za-z0-9_.:-]*$/D', $value) !== 1 || isset($state['ids'][$value])) {
                            $state['removedAttributes']++;
                            continue;
                        }
                        $state['ids'][$value] = true;
                    }
                    if (in_array($attrName, ['fill', 'stroke'], true) && (str_contains($value, '\\') || str_contains($value, '/*'))) {
                        $state['removedAttributes']++;
                        $state['unsafeAttributes']++;
                        continue;
                    }
                    if (preg_match('/url\s*\(/i', $value) === 1) {
                        if (preg_match('/^url\(#[A-Za-z_][A-Za-z0-9_.:-]*\)$/D', $value) !== 1) {
                            $state['removedAttributes']++;
                            $state['unsafeAttributes']++;
                            continue;
                        }
                        $state['references'][] = substr($value, 5, -1);
                    }
                    if (preg_match('/^(?:javascript|data|https?|file|ftp):/i', trim($value)) === 1) {
                        $state['removedAttributes']++;
                        $state['unsafeAttributes']++;
                        continue;
                    }
                    $this->append($state, ' ' . $attrName . '="' . $this->escapeAttribute($value) . '"');
                }
                $this->append($state, '>');
            }
            foreach ($node->childNodes as $child) {
                $this->serializeNode($child, $depth + 1, $blocked || !$allowed, false, $state);
            }
            if ($allowed) {
                $this->append($state, '</' . $name . '>');
            }
            return;
        }
        if (!$blocked && ($node->nodeType === XML_TEXT_NODE || $node->nodeType === XML_CDATA_SECTION_NODE)) {
            $this->append($state, $this->escapeText($node->nodeValue ?? ''));
        }
        if ($node->nodeType === XML_PI_NODE) {
            throw new SvgRejectedException('SVG processing instructions are not accepted.');
        }
    }

    /** @param array<string, mixed> $state */
    private function append(array &$state, string $text): void
    {
        if (strlen($state['output']) + strlen($text) > self::MAX_OUTPUT_BYTES) {
            throw new ResourceLimitExceededException('SVG output limit exceeded.');
        }
        $state['output'] .= $text;
    }

    private function escapeText(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_NOQUOTES, 'UTF-8');
    }

    private function escapeAttribute(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }

    /** @return array<string, mixed> */
    private function finding(string $id, string $title, string $description, string $severity, string $status, string $controlStatus): array
    {
        return [
            'id' => $id, 'severity' => $severity, 'stage' => 'active_content', 'title' => $title,
            'description' => $description, 'status' => $status, 'controlStatus' => $controlStatus,
            'evidence' => [['kind' => 'policy', 'summary' => $description]],
        ];
    }
}
