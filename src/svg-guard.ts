import { Buffer } from "node:buffer";
import { SaxesParser } from "saxes";
import { PixwardenError, type Finding, type ResourceLimits } from "./types.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const XMLNS_NS = "http://www.w3.org/2000/xmlns/";
const SVG_ELEMENTS = new Set([
  "svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
  "text", "tspan", "title", "desc", "defs", "linearGradient", "radialGradient", "stop",
  "clipPath", "mask", "pattern"
]);
const ACTIVE_ELEMENTS = new Set(["script", "style", "foreignObject", "iframe", "object", "embed", "image", "use", "a", "animate", "animateMotion", "animateTransform", "set", "audio", "video", "filter"]);
const SVG_ATTRIBUTES = new Set([
  "id", "class", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry",
  "width", "height", "viewBox", "preserveAspectRatio", "d", "points", "fill", "stroke",
  "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit", "fill-rule",
  "clip-rule", "opacity", "fill-opacity", "stroke-opacity", "transform", "offset",
  "stop-color", "stop-opacity", "gradientUnits", "gradientTransform", "spreadMethod",
  "patternUnits", "patternContentUnits", "patternTransform", "clipPathUnits", "maskUnits",
  "maskContentUnits", "font-family", "font-size", "font-weight", "text-anchor",
  "dominant-baseline", "shape-rendering", "vector-effect"
]);

const SVG_LIMITS = Object.freeze({ maxInputBytes: 2 * 1024 * 1024, maxNodes: 50_000, maxDepth: 64, maxAttributes: 100_000, maxOutputBytes: 4 * 1024 * 1024 });

interface SvgFrame {
  readonly name: string;
  readonly blocked: boolean;
}

interface InternalSvgResult {
  readonly output: string;
  readonly removedElements: ReadonlyMap<string, number>;
  readonly removedAttributes: number;
  readonly activeElements: number;
  readonly unsafeAttributes: number;
  readonly nodeCount: number;
}

export interface SvgSanitizationResult {
  readonly bytes: Uint8Array;
  readonly inputBytes: number;
  readonly outputBytes: number;
  readonly removedElements: Readonly<Record<string, number>>;
  readonly removedAttributes: number;
  readonly postCheckStatus: "passed";
}

export interface SvgInspection {
  readonly validity: "valid" | "invalid";
  readonly findings: readonly Finding[];
  readonly metadataBytes: number;
  readonly nodeCount: number;
}

function escapeText(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function escapeAttribute(value: string): string {
  return escapeText(value).replaceAll('"', "&quot;").replaceAll("'", "&apos;");
}

function isSafeLocalReference(value: string): boolean {
  return /^url\(#[A-Za-z_][A-Za-z0-9_.:-]*\)$/.test(value);
}

function addFinding(
  id: string,
  title: string,
  description: string,
  severity: Finding["severity"] = "medium",
  status: Finding["status"] = "inconclusive",
  controlStatus: Finding["controlStatus"] = "passed"
): Finding {
  return {
    id,
    severity,
    stage: "active_content",
    title,
    description,
    status,
    controlStatus,
    evidence: [{ kind: "policy", summary: description }]
  };
}

function parseAndSerializeSvg(bytes: Uint8Array, limits: ResourceLimits): InternalSvgResult {
  if (bytes.byteLength > Math.min(limits.maxBytes, SVG_LIMITS.maxInputBytes)) {
    throw new PixwardenError("INPUT_TOO_LARGE", "SVG input exceeds the configured SVG byte limit.");
  }
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new PixwardenError("MALFORMED_INPUT", "SVG input must be well-formed UTF-8.");
  }

  const parser = new SaxesParser({ xmlns: true });
  const stack: SvgFrame[] = [];
  const removedElements = new Map<string, number>();
  const ids = new Set<string>();
  const references: string[] = [];
  let output = "";
  let outputBytes = 0;
  let removedAttributes = 0;
  let activeElements = 0;
  let unsafeAttributes = 0;
  let nodeCount = 0;
  let attributeCount = 0;
  let rootSeen = false;

  const append = (text: string): void => {
    outputBytes += Buffer.byteLength(text, "utf8");
    if (outputBytes > SVG_LIMITS.maxOutputBytes) throw new PixwardenError("LIMIT_EXCEEDED", "Sanitized SVG output exceeds the configured output limit.");
    output += text;
  };

  parser.on("doctype", () => {
    throw new PixwardenError("MALFORMED_INPUT", "SVG document types and DTDs are not accepted.");
  });
  parser.on("processinginstruction", () => {
    throw new PixwardenError("MALFORMED_INPUT", "SVG processing instructions are not accepted.");
  });
  parser.on("error", () => {
    throw new PixwardenError("MALFORMED_INPUT", "SVG XML is not well-formed under the selected profile.");
  });
  parser.on("opentag", (tag) => {
    nodeCount++;
    if (nodeCount > SVG_LIMITS.maxNodes) throw new PixwardenError("LIMIT_EXCEEDED", "SVG node count exceeds the configured limit.");
    if (stack.length + 1 > SVG_LIMITS.maxDepth) throw new PixwardenError("LIMIT_EXCEEDED", "SVG nesting depth exceeds the configured limit.");
    const parentBlocked = stack.at(-1)?.blocked ?? false;
    const localName = tag.local;
    const root = stack.length === 0;
    if (root) {
      if (rootSeen || localName !== "svg" || tag.uri !== SVG_NS) throw new PixwardenError("MALFORMED_INPUT", "SVG root must be one element in the SVG namespace.");
      rootSeen = true;
    }
    const allowed = !parentBlocked && tag.uri === SVG_NS && SVG_ELEMENTS.has(localName);
    if (!allowed) {
      removedElements.set(localName, (removedElements.get(localName) ?? 0) + 1);
      if (!parentBlocked && ACTIVE_ELEMENTS.has(localName)) activeElements++;
    }
    const frame = { name: localName, blocked: !allowed };
    stack.push(frame);
    if (!allowed) return;

    append(`<${localName}`);
    if (root) append(` xmlns="${SVG_NS}"`);
    for (const attribute of Object.values(tag.attributes)) {
      attributeCount++;
      if (attributeCount > SVG_LIMITS.maxAttributes) throw new PixwardenError("LIMIT_EXCEEDED", "SVG attribute count exceeds the configured limit.");
      const attrName = attribute.local;
      const value = attribute.value;
      if (attribute.uri === XMLNS_NS || attribute.name === "xmlns" || attribute.prefix === "xmlns") continue;
      if (attribute.uri !== "" || !SVG_ATTRIBUTES.has(attrName) || value.length > 4096) {
        removedAttributes++;
        if (/^on/i.test(attrName) || ["href", "src", "style"].includes(attrName)) unsafeAttributes++;
        continue;
      }
      if (attrName === "id") {
        if (!/^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(value) || ids.has(value)) {
          removedAttributes++;
          continue;
        }
        ids.add(value);
      }
      if (/url\s*\(/i.test(value)) {
        if (!isSafeLocalReference(value)) {
          removedAttributes++;
          unsafeAttributes++;
          continue;
        }
        references.push(value.slice(5, -1));
      }
      if (/^(?:javascript|data|https?|file|ftp):/i.test(value.trim())) {
        removedAttributes++;
        unsafeAttributes++;
        continue;
      }
      append(` ${attrName}="${escapeAttribute(value)}"`);
    }
    append(">");
  });
  parser.on("closetag", () => {
    const frame = stack.pop();
    if (frame && !frame.blocked) append(`</${frame.name}>`);
  });
  parser.on("text", (text) => {
    if (stack.length > 0 && !stack.at(-1)!.blocked) append(escapeText(text));
  });
  parser.on("cdata", (text) => {
    if (stack.length > 0 && !stack.at(-1)!.blocked) append(escapeText(text));
  });

  try {
    parser.write(source);
    parser.close();
  } catch (error) {
    if (error instanceof PixwardenError) throw error;
    throw new PixwardenError("MALFORMED_INPUT", "SVG XML could not be parsed.");
  }
  if (!rootSeen || stack.length !== 0) throw new PixwardenError("MALFORMED_INPUT", "SVG document is incomplete.");
  for (const reference of references) {
    if (!ids.has(reference)) throw new PixwardenError("MALFORMED_INPUT", "SVG contains a local reference to an unknown identifier.");
  }
  return { output, removedElements, removedAttributes, activeElements, unsafeAttributes, nodeCount };
}

function toSafeLimits(): ResourceLimits {
  return { maxBytes: SVG_LIMITS.maxInputBytes, maxWidth: 40_000, maxHeight: 40_000, maxPixels: 40_000_000, maxFrames: 200, maxMetadataBytes: 1024 * 1024 };
}

export function inspectSvg(bytes: Uint8Array, limits: ResourceLimits): SvgInspection {
  try {
    const result = parseAndSerializeSvg(bytes, limits);
    const findings: Finding[] = [];
    if (result.removedElements.size > 0) findings.push(result.activeElements > 0
      ? addFinding("SVG-001", "Active SVG element removed", "The document contains an active or externally linked SVG element.", "high", "confirmed", "failed")
      : addFinding("SVG-001", "Unsupported SVG element removed", "One or more elements are outside the supported static SVG subset."));
    if (result.removedAttributes > 0) findings.push(result.unsafeAttributes > 0
      ? addFinding("SVG-002", "Active SVG attribute removed", "The document contains an event handler, active URL, or unsupported external reference.", "high", "confirmed", "failed")
      : addFinding("SVG-002", "Unsupported SVG attribute removed", "One or more attributes are outside the supported static SVG subset."));
    return { validity: "valid", findings, metadataBytes: 0, nodeCount: result.nodeCount };
  } catch (error) {
    const id = error instanceof PixwardenError && error.code === "LIMIT_EXCEEDED" ? "SVG-005" : "SVG-009";
    const finding = addFinding(id, "SVG could not be safely parsed", error instanceof Error ? error.message : "SVG parse failed.", "high", "confirmed", "failed");
    return { validity: "invalid", findings: [finding], metadataBytes: 0, nodeCount: 0 };
  }
}

export function sanitizeSvg(bytes: Uint8Array): SvgSanitizationResult {
  const limits = toSafeLimits();
  const result = parseAndSerializeSvg(bytes, limits);
  const output = new TextEncoder().encode(result.output);
  const verification = parseAndSerializeSvg(output, limits);
  if (verification.output !== result.output || verification.removedAttributes !== 0 || verification.removedElements.size !== 0) {
    throw new PixwardenError("SANITIZATION_FAILURE", "Sanitized SVG did not pass its post-sanitization check.");
  }
  return Object.freeze({
    bytes: output,
    inputBytes: bytes.byteLength,
    outputBytes: output.byteLength,
    removedElements: Object.freeze(Object.fromEntries(result.removedElements)),
    removedAttributes: result.removedAttributes,
    postCheckStatus: "passed"
  });
}
