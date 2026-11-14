# Steganography

**Status: not implemented.** Neither package currently estimates LSB, alpha-channel, palette, frame, coefficient, or statistical steganography. Reports expose `steganography.status: unsupported` with an empty method list and explicit limitations. No steganography adapter is bundled.

The security matrix lists candidate research and future methods only. A future detector must name its applicable formats and method, publish corpus version and benign controls, report precision/recall and false-positive/negative rates on separate evaluation data, and use suspected/inconclusive status when evidence is probabilistic. No universal detection claim is acceptable.

Metadata stripping does not remove pixel-level hidden data. PNG metadata transformation must not be presented as steganography mitigation.

## Research boundary

Steganalysis is method-specific: spatial LSB statistics and JPEG coefficient methods depend on the embedding algorithm, image source and processing history. RS analysis and F5 steganalysis are useful research baselines, not universal detectors. Any future implementation must state its supported format/profile and embedding assumptions, emit `inconclusive` outside that scope, and be measured on separated cover/stego sets with representative camera, editing, compression and synthetic image sources. Calibration must include false-positive rates; an uncalibrated anomaly score cannot be an automatic allow/reject gate.

References: [Fridrich et al., RS analysis](https://doi.org/10.1109/93.959097); [Ker, quantitative evaluation of pairs and RS analysis](https://www.cs.ox.ac.uk/people/andrew.ker/docs/ADK08B.pdf); [Kombrink et al., 2024 survey](https://doi.org/10.1145/3694965); [Fridrich et al., F5 JPEG steganalysis](https://ws.binghamton.edu/fridrich/Research/f5.pdf). Consulted 2026-11-14.
