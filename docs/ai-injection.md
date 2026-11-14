# AI and multimodal injection

**Status: not implemented.** Pixwarden currently has no OCR, VLM, prompt-injection classifier, region analysis, cross-image reasoning, RAG integration, or agent adapter. The core does not extract image text for instruction execution and makes no claim about downstream model behavior.

Treat images and OCR/model output as untrusted data. Apply application-specific taint handling, tool permissions, retrieval isolation, human review for consequential decisions, and explicit egress approval for any future hosted adapter. A future detector must be advisory, bounded, privacy-reviewed, and calibrated against benign text as well as attack simulations.
