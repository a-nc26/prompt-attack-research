#!/usr/bin/env python3
"""
refilter_db.py
--------------
Re-applies a strict adversarial relevance gate to ALL entries in master_db.json,
re-classifies taxonomy, severity, and rebuilds the database in place.

Usage:
    python3 refilter_db.py
"""

import json
import os
import re
import sys
from collections import Counter

DATA_DIR        = os.path.expanduser("~/ai_security_research/data")
MASTER_DB_PATH  = os.path.join(DATA_DIR, "master_db.json")

# ---------------------------------------------------------------------------
# HARD KEEP signals — any one present in selftext => candidate for keep
# ---------------------------------------------------------------------------

JAILBREAK_PHRASES = [
    "ignore previous instructions",
    "ignore all previous",
    "you are now",
    "act as if you have no",
    "you have no restrictions",
    "forget your training",
    "disregard your",
    "override your",
    "pretend you have no",
    "dan",
    "do anything now",
    "developer mode",
    "jailbreak mode",
    "unrestricted mode",
]

PERSONA_INJECTION_PATTERN = re.compile(
    r"act as\s+(an?\s+)?(AI|assistant|model|GPT|Claude|LLM|bot|expert|hacker|evil|uncensored|unfiltered|unaligned)",
    re.IGNORECASE,
)

SYSTEM_OVERRIDE_PHRASES = [
    "[system]",
    "[inst]",
    "### system:",
    "<<sys>>",
    "system prompt:",
    "ignore your previous",
    "new persona:",
    "you are an ai that",
]

ENCODING_TRICK_PATTERN = re.compile(
    r"(base64|rot13|leetspeak|pig latin|morse code).{0,80}(encode|decode|prompt)",
    re.IGNORECASE | re.DOTALL,
)
ENCODING_KEYWORD_DIRECT = [
    "base64",
    "rot13",
    "leetspeak",
    "pig latin",
]

EXTRACTION_PHRASES = [
    "repeat your instructions",
    "what is your system prompt",
    "reveal your instructions",
    "print your prompt",
    "output your system",
    "leak your",
]

EXTRACTION_PATTERNS = re.compile(
    r"(leaked?\s+(the\s+)?system\s+prompt|system\s+prompt\s+(leak|extract|dump|reveal|exfil))",
    re.IGNORECASE,
)

MULTI_TURN_PHRASES = [
    "crescendo",
    "gradually escalate",
    "each turn",
    "build up to",
]

INJECTION_PHRASES = [
    "prompt injection",
    "indirect injection",
    "ignore the above",
    "ignore above instructions",
]

RESEARCH_PHRASES = [
    "red team",
    "red-team",
    "adversarial prompt",
    "jailbreak technique",
    "safety bypass",
    "guardrail bypass",
    "prompt attack",
    "llm vulnerability",
    "jailbreak evaluation",
    "attack success rate",
]

# ---------------------------------------------------------------------------
# HARD EXCLUDE signals — any one present => exclude (overrides KEEP)
# ---------------------------------------------------------------------------

SEO_MARKETING_PHRASES = [
    "seo",
    "meta title",
    "meta description",
    "keyword research",
    "outrank",
    "targetlanguage",
    "promptpackage",
    "prompthint",
    "redbubble",
    "etsy",
    "ecommerce",
    "e-commerce",
    "product description",
    "click-through rate",
    "conversion rate",
]

PLATFORM_NOISE_PHRASES = [
    "or is down",
    "app not working",
    "server error",
    "can't login",
    "cannot login",
]

BENIGN_START_PATTERN = re.compile(
    r"^(Write a|Create a|Generate a|Summarize|Translate)\s",
    re.IGNORECASE,
)

# Adversarial indicators needed to rescue a benign-start entry
ADVERSARIAL_RESCUE_PHRASES = [
    "ignore previous instructions",
    "ignore all previous",
    "you are now",
    "act as if you have no",
    "you have no restrictions",
    "forget your training",
    "disregard your",
    "override your",
    "pretend you have no",
    "dan",
    "do anything now",
    "developer mode",
    "jailbreak mode",
    "unrestricted mode",
    "base64",
    "rot13",
    "leetspeak",
    "repeat your instructions",
    "what is your system prompt",
    "reveal your instructions",
    "print your prompt",
    "output your system",
    "leak your",
    "crescendo",
    "gradually escalate",
    "prompt injection",
    "indirect injection",
    "ignore the above",
    "ignore above instructions",
    "red team",
    "red-team",
    "adversarial prompt",
    "jailbreak technique",
    "safety bypass",
    "guardrail bypass",
    "[system]",
    "[inst]",
    "### system:",
    "<<sys>>",
    "system prompt:",
    "new persona:",
    "you are an ai that",
]


# ---------------------------------------------------------------------------
# TAXONOMY CLASSIFICATION
# ---------------------------------------------------------------------------

TAXONOMY_SIGNALS = {
    "Role & Persona Manipulation": [
        "act as",
        "you are now",
        "dan",
        "persona",
        "pretend to be",
        "you have no restrictions",
        "unrestricted",
        "developer mode",
        "new persona",
    ],
    "Instruction Hierarchy Attacks": [
        "ignore previous",
        "ignore all",
        "override",
        "forget your",
        "disregard",
        "new instructions",
        "supersede",
        "[system]",
        "<<sys>>",
    ],
    "Encoding & Obfuscation": [
        "base64",
        "rot13",
        "leetspeak",
        "encode",
        "cipher",
        "obfuscat",
        "pig latin",
    ],
    "Fictional Framing": [
        "hypothetically",
        "in a story",
        "fictional world",
        "imagine a scenario",
        "creative writing exercise",
    ],
    "Social Engineering": [
        "my life depends",
        "emergency",
        "i'll be fired",
        "please i need",
        "trust me",
        "i'm a doctor",
        "i'm a researcher",
        "for educational purposes only",
    ],
    "Divide & Conquer / Multi-turn": [
        "crescendo",
        "multi-turn",
        "gradually",
        "each step",
        "build up",
        "across turns",
    ],
    "Indirect & Prompt Injection": [
        "prompt injection",
        "indirect injection",
        "ignore the above",
        "injected via",
        "tool call",
        "via document",
    ],
    "Model Extraction": [
        "repeat your instructions",
        "system prompt",
        "reveal your",
        "what were you told",
        "print your",
        "leak your",
        "your initial prompt",
    ],
    "Defense & Red-team Research": [
        "red team",
        "red-team",
        "adversarial",
        "safety evaluation",
        "jailbreak detection",
        "guardrail",
        "robustness",
        "attack success",
    ],
}

# Priority order for taxonomy (first match wins)
TAXONOMY_ORDER = [
    "Instruction Hierarchy Attacks",
    "Role & Persona Manipulation",
    "Encoding & Obfuscation",
    "Fictional Framing",
    "Social Engineering",
    "Divide & Conquer / Multi-turn",
    "Indirect & Prompt Injection",
    "Model Extraction",
    "Defense & Red-team Research",
]


def classify_taxonomy(selftext: str) -> str:
    """Return the best-matching taxonomy category for the given text."""
    low = selftext.lower() if selftext else ""
    for cat in TAXONOMY_ORDER:
        signals = TAXONOMY_SIGNALS[cat]
        if any(sig in low for sig in signals):
            return cat
    return "Role & Persona Manipulation"  # default for jailbreak content


def classify_severity(taxonomy_category: str, selftext: str) -> str:
    """Assign severity based on taxonomy and presence of actual prompt text."""
    if taxonomy_category == "Defense & Red-team Research":
        return "Info"
    if taxonomy_category in ("Role & Persona Manipulation", "Instruction Hierarchy Attacks"):
        # Check if it looks like an actual prompt (not just a named technique)
        low = (selftext or "").lower()
        # Must have actual prompt-like content
        if len(selftext or "") > 200:
            return "High"
        if any(p in low for p in ["you are now", "ignore all", "ignore previous", "act as"]):
            return "High"
        return "Medium"
    if taxonomy_category in (
        "Encoding & Obfuscation",
        "Fictional Framing",
        "Social Engineering",
        "Divide & Conquer / Multi-turn",
        "Indirect & Prompt Injection",
        "Model Extraction",
    ):
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# GATE FUNCTION
# ---------------------------------------------------------------------------

def is_adversarial(selftext: str) -> bool:
    """
    Returns True iff selftext passes the strict adversarial relevance gate.

    Hard EXCLUDE signals override hard KEEP signals.
    """
    if not selftext or not isinstance(selftext, str):
        return False

    text = selftext.strip()
    low  = text.lower()

    # ---- HARD EXCLUDE FIRST ----

    # Too short
    if len(text) < 50:
        return False

    # SEO / marketing content
    if any(phrase in low for phrase in SEO_MARKETING_PHRASES):
        return False

    # Template placeholders only (3+ occurrences with no real adversarial content)
    placeholder_count = (
        low.count("[prompt]")
        + low.count("[target]")
        + sum(1 for _ in re.finditer(r"\[variable", low))
    )
    if placeholder_count >= 3:
        # Only exclude if no real adversarial content
        has_adversarial = (
            any(p in low for p in ADVERSARIAL_RESCUE_PHRASES)
            or bool(PERSONA_INJECTION_PATTERN.search(text))
            or bool(EXTRACTION_PATTERNS.search(text))
        )
        if not has_adversarial:
            return False

    # Platform noise
    if any(phrase in low for phrase in PLATFORM_NOISE_PHRASES):
        return False

    # Auto-generated classifier descriptions that replaced real selftext in a
    # previous pipeline run — these are NOT actual prompts.
    AUTO_DESCRIPTION_SIGNALS = [
        "unrelated to adversarial prompting",
        "not focused on adversarial prompting",
        "platform discussion covering",
        "platform technical support",
        "not an adversarial",
        "not focused on adversarial",
        "ai-generated tabletop",
        "agi timeline commentary",
        "general prompt engineering technique",
        # Classifier-generated rejection phrases that replaced real selftext
        "unrelated to llm adversarial",
        "not directly about llm adversarial",
        "not about llm adversarial",
        "not an adversarial prompt",
        "does not contain adversarial",
        "jailbreak' terminology; unrelated",
        "not directly about adversarial",
        "blue team data science",
    ]
    if any(sig in low for sig in AUTO_DESCRIPTION_SIGNALS):
        return False

    # Benign task start with no adversarial indicators
    if BENIGN_START_PATTERN.match(text):
        has_adversarial = (
            any(p in low for p in ADVERSARIAL_RESCUE_PHRASES)
            or bool(PERSONA_INJECTION_PATTERN.search(text))
            or bool(EXTRACTION_PATTERNS.search(text))
        )
        if not has_adversarial:
            return False

    # ---- HARD KEEP SIGNALS ----

    # Explicit jailbreak phrases
    if any(phrase in low for phrase in JAILBREAK_PHRASES):
        return True

    # Persona injection pattern
    if PERSONA_INJECTION_PATTERN.search(text):
        return True

    # System override phrases
    if any(phrase in low for phrase in SYSTEM_OVERRIDE_PHRASES):
        return True

    # Encoding tricks (keyword + encode/decode/prompt nearby)
    if ENCODING_TRICK_PATTERN.search(text):
        return True
    # Direct encoding keywords that are clearly about encoding prompts
    for kw in ENCODING_KEYWORD_DIRECT:
        if kw in low and ("encode" in low or "decode" in low or "prompt" in low):
            return True

    # Extraction attempts
    if any(phrase in low for phrase in EXTRACTION_PHRASES):
        return True
    if EXTRACTION_PATTERNS.search(text):
        return True

    # Multi-turn escalation
    if any(phrase in low for phrase in MULTI_TURN_PHRASES):
        return True

    # Injection via content
    if any(phrase in low for phrase in INJECTION_PHRASES):
        return True

    # Research / defense
    if any(phrase in low for phrase in RESEARCH_PHRASES):
        return True

    return False


# ---------------------------------------------------------------------------
# MAIN LOGIC
# ---------------------------------------------------------------------------

def main():
    print("=" * 65)
    print("refilter_db.py — Strict Adversarial Relevance Gate")
    print("=" * 65)
    print()

    if not os.path.exists(MASTER_DB_PATH):
        print(f"ERROR: master_db.json not found at {MASTER_DB_PATH}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {MASTER_DB_PATH}...")
    with open(MASTER_DB_PATH, "r", encoding="utf-8") as f:
        db = json.load(f)

    total_before = len(db)
    print(f"Total entries before: {total_before:,}")
    print()

    # Track examples for reporting
    newly_excluded = []   # was relevant=True, now relevant=False
    correctly_kept = []   # relevant=True and still True

    kept_count      = 0
    excluded_count  = 0

    for entry in db:
        selftext    = entry.get("selftext", "") or ""
        was_relevant = bool(entry.get("relevant"))
        now_relevant = is_adversarial(selftext)

        # Update relevant field
        entry["relevant"] = now_relevant

        if now_relevant:
            # Re-classify taxonomy and severity
            new_cat = classify_taxonomy(selftext)
            entry["taxonomy_category"] = new_cat
            entry["severity"]          = classify_severity(new_cat, selftext)

            kept_count += 1
            if len(correctly_kept) < 3:
                correctly_kept.append(entry)
        else:
            excluded_count += 1
            if was_relevant and len(newly_excluded) < 3:
                newly_excluded.append(entry)

    # ---- Save ----
    print(f"Saving updated master_db.json...")
    with open(MASTER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    size_bytes = os.path.getsize(MASTER_DB_PATH)

    # ---- Report ----
    print()
    print("=" * 65)
    print("RESULTS")
    print("=" * 65)
    print(f"  Total entries (unchanged):  {total_before:,}")
    print(f"  Relevant after filtering:   {kept_count:,}")
    print(f"  Excluded after filtering:   {excluded_count:,}")
    print(f"  DB file size:               {size_bytes:,} bytes ({size_bytes / 1024 / 1024:.1f} MB)")
    print()

    # Breakdown by taxonomy (relevant only)
    cat_counts = Counter(
        e["taxonomy_category"] for e in db if e.get("relevant")
    )
    print("Breakdown by taxonomy_category (relevant only):")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
        bar = "#" * min(40, count // 20)
        print(f"  {cat:<40} {count:>5}  {bar}")
    print()

    # Examples of newly excluded (were relevant, now not)
    print("=" * 65)
    print("Examples of 3 entries that WERE relevant → NOW EXCLUDED (noise removal confirmed):")
    print("=" * 65)
    for i, e in enumerate(newly_excluded):
        print(f"\n  [{i+1}] Title: {(e.get('title') or '')[:80]}")
        print(f"       Category (old): {e.get('taxonomy_category', 'N/A')}")
        print(f"       Selftext[:200]: {(e.get('selftext') or '')[:200]!r}")

    if not newly_excluded:
        print("  (no entries newly excluded — all excluded entries were already marked non-relevant)")

    # Examples of correctly kept
    print()
    print("=" * 65)
    print("Examples of 3 entries CORRECTLY KEPT (adversarial content confirmed):")
    print("=" * 65)
    for i, e in enumerate(correctly_kept):
        print(f"\n  [{i+1}] Title: {(e.get('title') or '')[:80]}")
        print(f"       Category: {e.get('taxonomy_category', 'N/A')}")
        print(f"       Severity: {e.get('severity', 'N/A')}")
        print(f"       Selftext[:200]: {(e.get('selftext') or '')[:200]!r}")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
