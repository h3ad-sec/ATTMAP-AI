# ATTMAP-AI

**ATT&CK Technique Mapper — Part of [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/)**

ATTMAP-AI maps threat descriptions, incident summaries, or analyst observations to MITRE ATT&CK techniques. Paste raw text — alert context, analyst notes, malware behavior, or threat reports — and get a structured technique breakdown with tactic coverage, confidence ratings, relevance explanations, detection gaps, and hunting pivots.

## Features

- Supports four AI providers: Anthropic (Claude), OpenAI (GPT), Google Gemini, Groq
- Identifies specific ATT&CK sub-techniques (not just top-level tactics)
- Confidence rating per technique: HIGH / MEDIUM / LOW
- Tactic coverage map showing which ATT&CK phases are present
- Detection gap analysis per technique
- Hunting pivots for immediate threat hunting follow-up
- Direct links to attack.mitre.org for every identified technique
- Clean, analyst-readable output
- Fully responsive — works on mobile, tablet, and desktop

## Output Sections

| Section | Content |
|---------|---------|
| Technique Cards | ID, name, tactic, confidence, relevance explanation |
| Tactic Coverage | Visual coverage across the ATT&CK matrix phases |
| Detection Gaps | Where visibility is missing for identified techniques |
| Hunting Pivots | Specific hunt leads derived from the technique set |

## How to Use

1. Add your API key via the settings icon
2. Paste threat description, incident context, or analyst notes
3. Click ANALYZE
4. Review the technique breakdown and tactic coverage

## Live Tool

[h3ad-sec.github.io/ATTMAP-AI](https://h3ad-sec.github.io/ATTMAP-AI/)

## Part of H3AD-SEC

ATTMAP-AI is a sub-tool under [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/), the AI-assisted analysis hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.

## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, MALBRIEF-AI |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG, PHISHOPS |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | — |
