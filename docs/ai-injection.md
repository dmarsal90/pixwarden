# AI and multimodal injection

## Current capability

An opt-in, local rule set inspects PNG `tEXt`, `zTXt` and `iTXt` fields for a small set of explicit English and Spanish instruction-override phrases. Compressed fields are expanded only up to the remaining metadata budget; a malformed field, an unavailable decompressor, or a field that exceeds the bound makes the result partial. In PHP, `ext-zlib` is required to inspect compressed fields. The analyzer emits an advisory `AI-002` suspected signal and does not include matched text in reports. Use `ScanOptions.aiInspection: { enabled: true, ocr: false }` in JS or `AiInspectionOptions(enabled: true, ocr: false)` in PHP. No network or model call occurs.

The scan report marks a complete bounded rule-set pass as `completed`, identifies `dataEgress: none`, and includes its limitations. If metadata could not be fully inspected, the status is `partial`, the AI control is unsupported, and policy cannot treat the AI check as passed. A suspicious text match results in `review` under current verdict rules; it is not proof of malicious intent. Benign metadata may contain similar language, and the rules can miss paraphrases, encodings, languages, and text stored in unsupported metadata forms.

## Unsupported capabilities

- OCR and inspection of visible pixels.
- Non-PNG metadata text and metadata formats beyond PNG text chunks.
- Region grouping, cross-image reasoning, VLM classification, adversarial vision testing, RAG or agent integration.
- Universal prompt-injection prevention or claims about downstream model behavior.

Setting `ocr: true` records a partial result and an unsupported OCR control; it does not invoke OCR. Findings are never executed. Treat all image-derived text as untrusted data, apply least privilege to downstream agents, and gate consequential actions in the consuming application.
