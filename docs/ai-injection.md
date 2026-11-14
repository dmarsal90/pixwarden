# AI and multimodal injection

## Current capability

An opt-in, local rule set inspects uncompressed PNG `tEXt` and uncompressed `iTXt` fields for a small set of explicit English and Spanish instruction-override phrases. It emits an advisory `AI-002` suspected signal and does not include matched text in reports. Use `ScanOptions.aiInspection: { enabled: true, ocr: false }` in JS or `AiInspectionOptions(enabled: true, ocr: false)` in PHP. No network or model call occurs.

The scan report marks the rule-set run as `completed`, identifies `dataEgress: none`, and includes its limitations. A suspicious text match results in `review` under current verdict rules; it is not proof of malicious intent. Benign metadata may contain similar language, and the rules can miss paraphrases, encodings, languages, and text stored in unsupported metadata forms.

## Unsupported capabilities

- OCR and inspection of visible pixels.
- Compressed PNG text chunks and non-PNG metadata text.
- Region grouping, cross-image reasoning, VLM classification, adversarial vision testing, RAG or agent integration.
- Universal prompt-injection prevention or claims about downstream model behavior.

Setting `ocr: true` records a partial result and an unsupported OCR control; it does not invoke OCR. Findings are never executed. Treat all image-derived text as untrusted data, apply least privilege to downstream agents, and gate consequential actions in the consuming application.
