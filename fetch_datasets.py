#!/usr/bin/env python3
"""
fetch_datasets.py
-----------------
Downloads Tier 1 AI security research datasets (MIT or Apache-2.0 licensed,
no login required), normalizes entries into the master_db schema, deduplicates
against existing master_db.json, and appends new entries.

All sources verified as MIT or Apache-2.0 licensed, freely accessible.
"""

import csv
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import time
import warnings
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Strict adversarial relevance gate
# ---------------------------------------------------------------------------
# This gate must be applied to every entry BEFORE adding it to the DB.
# It mirrors the logic in refilter_db.py exactly so that future ingestion
# runs do not re-introduce SEO/marketing/benign noise.

_JAILBREAK_PHRASES = [
    "ignore previous instructions", "ignore all previous", "you are now",
    "act as if you have no", "you have no restrictions", "forget your training",
    "disregard your", "override your", "pretend you have no", "dan",
    "do anything now", "developer mode", "jailbreak mode", "unrestricted mode",
]

_PERSONA_INJECTION_RE = re.compile(
    r"act as\s+(an?\s+)?(AI|assistant|model|GPT|Claude|LLM|bot|expert|hacker|evil|uncensored|unfiltered|unaligned)",
    re.IGNORECASE,
)

_SYSTEM_OVERRIDE_PHRASES = [
    "[system]", "[inst]", "### system:", "<<sys>>", "system prompt:",
    "ignore your previous", "new persona:", "you are an ai that",
]

_ENCODING_TRICK_RE = re.compile(
    r"(base64|rot13|leetspeak|pig latin|morse code).{0,80}(encode|decode|prompt)",
    re.IGNORECASE | re.DOTALL,
)
_ENCODING_DIRECT = ["base64", "rot13", "leetspeak", "pig latin"]

_EXTRACTION_PHRASES = [
    "repeat your instructions", "what is your system prompt",
    "reveal your instructions", "print your prompt",
    "output your system", "leak your",
]

_MULTI_TURN_PHRASES = [
    "crescendo", "gradually escalate", "each turn", "build up to",
]

_INJECTION_PHRASES = [
    "prompt injection", "indirect injection",
    "ignore the above", "ignore above instructions",
]

_RESEARCH_PHRASES = [
    "red team", "red-team", "adversarial prompt", "jailbreak technique",
    "safety bypass", "guardrail bypass", "prompt attack",
    "llm vulnerability", "jailbreak evaluation", "attack success rate",
]

_SEO_MARKETING_PHRASES = [
    "seo", "meta title", "meta description", "keyword research", "outrank",
    "targetlanguage", "promptpackage", "prompthint", "redbubble", "etsy",
    "ecommerce", "e-commerce", "product description",
    "click-through rate", "conversion rate",
]

_PLATFORM_NOISE_PHRASES = [
    "or is down", "app not working", "server error", "can't login", "cannot login",
]

_BENIGN_START_RE = re.compile(
    r"^(Write a|Create a|Generate a|Summarize|Translate)\s",
    re.IGNORECASE,
)

_ADVERSARIAL_RESCUE_PHRASES = [
    "ignore previous instructions", "ignore all previous", "you are now",
    "act as if you have no", "you have no restrictions", "forget your training",
    "disregard your", "override your", "pretend you have no", "dan",
    "do anything now", "developer mode", "jailbreak mode", "unrestricted mode",
    "base64", "rot13", "leetspeak", "repeat your instructions",
    "what is your system prompt", "reveal your instructions",
    "print your prompt", "output your system", "leak your",
    "crescendo", "gradually escalate", "prompt injection",
    "indirect injection", "ignore the above", "ignore above instructions",
    "red team", "red-team", "adversarial prompt", "jailbreak technique",
    "safety bypass", "guardrail bypass", "[system]", "[inst]",
    "### system:", "<<sys>>", "system prompt:", "new persona:", "you are an ai that",
]


def is_adversarial(selftext: str) -> bool:
    """
    Returns True iff selftext contains genuine adversarial content.

    Apply this gate to every entry before adding it to master_db so that
    SEO templates, marketing copy, and benign prompts are never ingested.

    Hard EXCLUDE signals are checked first and override all KEEP signals.
    """
    if not selftext or not isinstance(selftext, str):
        return False

    text = selftext.strip()
    low  = text.lower()

    # ---- HARD EXCLUDE ----
    if len(text) < 50:
        return False

    if any(p in low for p in _SEO_MARKETING_PHRASES):
        return False

    placeholder_count = (
        low.count("[prompt]")
        + low.count("[target]")
        + sum(1 for _ in re.finditer(r"\[variable", low))
    )
    if placeholder_count >= 3:
        if not (any(p in low for p in _ADVERSARIAL_RESCUE_PHRASES)
                or _PERSONA_INJECTION_RE.search(text)):
            return False

    if any(p in low for p in _PLATFORM_NOISE_PHRASES):
        return False

    # Auto-generated classifier descriptions that are NOT real prompts
    _AUTO_DESCRIPTION_SIGNALS = [
        "unrelated to adversarial prompting",
        "not focused on adversarial prompting",
        "platform discussion covering",
        "platform technical support",
        "not an adversarial",
        "ai-generated tabletop",
        "agi timeline commentary",
        "general prompt engineering technique",
    ]
    if any(sig in low for sig in _AUTO_DESCRIPTION_SIGNALS):
        return False

    if _BENIGN_START_RE.match(text):
        if not (any(p in low for p in _ADVERSARIAL_RESCUE_PHRASES)
                or _PERSONA_INJECTION_RE.search(text)):
            return False

    # ---- HARD KEEP ----
    if any(p in low for p in _JAILBREAK_PHRASES):
        return True
    if _PERSONA_INJECTION_RE.search(text):
        return True
    if any(p in low for p in _SYSTEM_OVERRIDE_PHRASES):
        return True
    if _ENCODING_TRICK_RE.search(text):
        return True
    for kw in _ENCODING_DIRECT:
        if kw in low and ("encode" in low or "decode" in low or "prompt" in low):
            return True
    if any(p in low for p in _EXTRACTION_PHRASES):
        return True
    if any(p in low for p in _MULTI_TURN_PHRASES):
        return True
    if any(p in low for p in _INJECTION_PHRASES):
        return True
    if any(p in low for p in _RESEARCH_PHRASES):
        return True

    return False

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
try:
    import requests
    USE_REQUESTS = True
except ImportError:
    import urllib.request
    USE_REQUESTS = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.expanduser("~/ai_security_research")
DATA_DIR = os.path.join(BASE_DIR, "data")
MASTER_DB_PATH = os.path.join(DATA_DIR, "master_db.json")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TAXONOMY_CATEGORIES = [
    "Role & Persona Manipulation",
    "Instruction Hierarchy Attacks",
    "Encoding & Obfuscation",
    "Fictional Framing",
    "Defense & Red-team Research",
    "Indirect & Prompt Injection",
    "General AI/LLM Discussion",
    "Other/Unclassified",
]

ROLE_KEYWORDS = ["act as", "you are", "pretend", "dan", "roleplay", "jailbreak"]
INSTRUCTION_KEYWORDS = ["ignore", "override", "forget your", "disregard", "bypass"]
ENCODING_KEYWORDS = ["base64", "encode", "cipher", "hex", "rot13", "obfuscat"]
FICTION_KEYWORDS = ["story", "fiction", "hypothetical", "imagine", "scenario", "novel"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def content_hash(text: str) -> str:
    """SHA-256 hash of text, first 16 hex chars."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def infer_taxonomy(selftext: str, source_dataset: str = "") -> str:
    """Heuristic taxonomy category from prompt text and source."""
    low = selftext.lower() if selftext else ""
    src = source_dataset.lower()

    # Source-based overrides first
    if any(x in src for x in ["harmbench", "wmdp", "hh-rlhf", "hh_rlhf", "anthropic"]):
        return "Defense & Red-team Research"
    if any(x in src for x in ["prompt-inject", "giskard", "latent-jailbreak", "latent_jailbreak",
                                "deepset", "gandalf"]):
        return "Indirect & Prompt Injection"

    # Text-based heuristics
    if any(kw in low for kw in ENCODING_KEYWORDS):
        return "Encoding & Obfuscation"
    if any(kw in low for kw in FICTION_KEYWORDS):
        return "Fictional Framing"
    if any(kw in low for kw in INSTRUCTION_KEYWORDS):
        return "Instruction Hierarchy Attacks"
    if any(kw in low for kw in ROLE_KEYWORDS):
        return "Role & Persona Manipulation"

    return "Role & Persona Manipulation"  # default for jailbreak datasets


def infer_severity(has_prompt: bool, taxonomy_category: str, relevant: bool) -> str:
    """Infer severity from context."""
    if not has_prompt:
        return "Low"
    defense_cats = {"Defense & Red-team Research", "General AI/LLM Discussion"}
    if taxonomy_category in defense_cats:
        return "Info"
    if relevant and has_prompt:
        return "High"
    return "Medium"


def make_entry(
    selftext: str,
    source_dataset: str,
    permalink: str,
    subreddit: str,
    relevant: bool = True,
    title: Optional[str] = None,
    taxonomy_category: Optional[str] = None,
    author: Optional[str] = None,
) -> dict:
    """Build a normalized schema entry."""
    selftext = (selftext or "").strip()
    if not selftext:
        return None

    h = content_hash(selftext)
    if not title:
        title = selftext[:80]
    if not taxonomy_category:
        taxonomy_category = infer_taxonomy(selftext, source_dataset)

    has_prompt = bool(selftext)
    severity = infer_severity(has_prompt, taxonomy_category, relevant)

    return {
        "id": h,
        "title": title[:80],
        "selftext": selftext,
        "author": author or source_dataset,
        "subreddit": subreddit,
        "permalink": permalink,
        "url": permalink,
        "score": 0,
        "num_comments": 0,
        "created_utc": 0,
        "is_self": True,
        "link_flair_text": "",
        "relevant": relevant,
        "taxonomy_category": taxonomy_category,
        "technique_name": taxonomy_category,
        "technique_description": f"Entry from {source_dataset} dataset.",
        "example_prompt": selftext[:600] if relevant else None,
        "persona_role": None,
        "severity": severity,
        "has_actual_prompt": has_prompt,
        "source_dataset": source_dataset,
    }


# ---------------------------------------------------------------------------
# Download utilities
# ---------------------------------------------------------------------------

def fetch_bytes(url: str, timeout: int = 60) -> Optional[bytes]:
    """Download raw bytes from a URL, return None on failure."""
    try:
        if USE_REQUESTS:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "ai-security-research/1.0"})
            if resp.status_code == 200:
                return resp.content
            print(f"    [WARN] HTTP {resp.status_code} for {url}")
            return None
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "ai-security-research/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
    except Exception as e:
        print(f"    [WARN] Failed to fetch {url}: {e}")
        return None


def fetch_parquet(url: str) -> Optional["pd.DataFrame"]:
    """Download a parquet file and return as DataFrame."""
    if not PANDAS_AVAILABLE:
        print("    [WARN] pandas not available, skipping parquet source")
        return None
    data = fetch_bytes(url)
    if data is None:
        return None
    try:
        df = pd.read_parquet(io.BytesIO(data))
        return df
    except Exception as e:
        print(f"    [WARN] Failed to parse parquet from {url}: {e}")
        return None


def fetch_csv_text(url: str) -> Optional[str]:
    """Download CSV file and return as text."""
    data = fetch_bytes(url)
    if data is None:
        return None
    try:
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"    [WARN] Failed to decode CSV from {url}: {e}")
        return None


def fetch_jsonl_gz(url: str, limit: Optional[int] = None) -> Optional[list]:
    """Download gzipped JSONL and return list of dicts."""
    data = fetch_bytes(url)
    if data is None:
        return None
    try:
        with gzip.open(io.BytesIO(data), "rt", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if limit and i >= limit:
                    break
                line = line.strip()
                if line:
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return lines
    except Exception as e:
        print(f"    [WARN] Failed to decompress/parse JSONL.gz from {url}: {e}")
        return None


def fetch_jsonl(url: str, limit: Optional[int] = None) -> Optional[list]:
    """Download JSONL file and return list of dicts."""
    data = fetch_bytes(url)
    if data is None:
        return None
    try:
        text = data.decode("utf-8", errors="replace")
        lines = []
        for i, line in enumerate(text.splitlines()):
            if limit and i >= limit:
                break
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return lines
    except Exception as e:
        print(f"    [WARN] Failed to parse JSONL from {url}: {e}")
        return None


# ---------------------------------------------------------------------------
# Source fetchers
# ---------------------------------------------------------------------------

def fetch_deepset_prompt_injections() -> list:
    """deepset/prompt-injections (Apache-2.0)"""
    source = "deepset/prompt-injections"
    # Actual file path discovered via HF API tree listing
    url = "https://huggingface.co/datasets/deepset/prompt-injections/resolve/main/data/train-00000-of-00001-9564e8b05b4757ab.parquet"
    print(f"  Fetching {source}...")
    df = fetch_parquet(url)
    if df is None:
        return []
    entries = []
    for _, row in df.iterrows():
        text = str(row.get("text", "") or "").strip()
        label = row.get("label", 0)
        if not text:
            continue
        is_injection = (label == 1)
        tax = "Indirect & Prompt Injection" if is_injection else "General AI/LLM Discussion"
        entry = make_entry(
            selftext=text,
            source_dataset=source,
            permalink=url,
            subreddit="HuggingFace",
            relevant=is_injection,
            taxonomy_category=tax,
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_jackhhao_jailbreak_classification() -> list:
    """jackhhao/jailbreak-classification (Apache-2.0) — CSV format"""
    source = "jackhhao/jailbreak-classification"
    # Dataset uses CSV files, not parquet. Discovered via HF API.
    url = "https://huggingface.co/datasets/jackhhao/jailbreak-classification/resolve/main/default/jailbreak_dataset_train.csv"
    print(f"  Fetching {source}...")
    text = fetch_csv_text(url)
    if text is None:
        return []
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        prompt = str(row.get("prompt", "") or "").strip()
        ptype = str(row.get("type", "") or "").strip().lower()
        if not prompt:
            continue
        relevant = (ptype == "jailbreak")
        entry = make_entry(
            selftext=prompt,
            source_dataset=source,
            permalink=url,
            subreddit="HuggingFace",
            relevant=relevant,
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_walledai_jailbreakhub() -> list:
    """walledai/JailbreakHub (MIT)"""
    source = "walledai/JailbreakHub"
    url = "https://huggingface.co/datasets/walledai/JailbreakHub/resolve/main/data/train-00000-of-00001.parquet"
    print(f"  Fetching {source}...")
    df = fetch_parquet(url)
    if df is None:
        return []
    entries = []
    for _, row in df.iterrows():
        prompt = str(row.get("prompt", "") or "").strip()
        if not prompt:
            continue
        entry = make_entry(
            selftext=prompt,
            source_dataset=source,
            permalink=url,
            subreddit="HuggingFace",
            relevant=True,
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_trustairlab_in_the_wild() -> list:
    """TrustAIRLab/in-the-wild-jailbreak-prompts (MIT)"""
    source = "TrustAIRLab/in-the-wild-jailbreak-prompts"
    # Actual path discovered via HF API — dataset is partitioned by date
    url = "https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts/resolve/main/jailbreak_2023_12_25/train-00000-of-00001.parquet"
    print(f"  Fetching {source}...")
    df = fetch_parquet(url)
    if df is None:
        return []
    entries = []
    for _, row in df.iterrows():
        prompt = str(row.get("prompt", "") or "").strip()
        if not prompt:
            continue
        entry = make_entry(
            selftext=prompt,
            source_dataset=source,
            permalink=url,
            subreddit="HuggingFace",
            relevant=True,
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_jailbreakbench_jbb_behaviors() -> list:
    """JailbreakBench/JBB-Behaviors (MIT) — CSV format"""
    source = "JailbreakBench/JBB-Behaviors"
    # Dataset uses CSV files. Fields: Index,Goal,Target,Behavior,Category,Source
    url = "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/harmful-behaviors.csv"
    print(f"  Fetching {source}...")
    text = fetch_csv_text(url)
    if text is None:
        return []
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        # Use Goal as the primary prompt field; Behavior is a short label
        behavior = (row.get("Goal") or row.get("Behavior") or "").strip()
        category = (row.get("Category") or "").strip()
        if not behavior:
            continue
        cat_low = category.lower()
        if any(x in cat_low for x in ["chemical", "biological", "weapon", "nuclear"]):
            tax = "Defense & Red-team Research"
        elif any(x in cat_low for x in ["cyber", "hack", "malware"]):
            tax = "Instruction Hierarchy Attacks"
        elif any(x in cat_low for x in ["harassment", "discrimination", "fraud"]):
            tax = "Role & Persona Manipulation"
        else:
            tax = infer_taxonomy(behavior, source)
        entry = make_entry(
            selftext=behavior,
            source_dataset=source,
            permalink=url,
            subreddit="HuggingFace",
            relevant=True,
            title=behavior[:80],
            taxonomy_category=tax,
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_lakera_gandalf() -> list:
    """Lakera/gandalf_ignore_instructions (MIT)"""
    source = "Lakera/gandalf_ignore_instructions"
    # Actual file path discovered via HF API tree listing
    url = "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions/resolve/main/data/train-00000-of-00001-ded53be747ff55cd.parquet"
    print(f"  Fetching {source}...")
    df = fetch_parquet(url)
    if df is None:
        return []
    entries = []
    for _, row in df.iterrows():
        text = str(row.get("text", "") or "").strip()
        label = row.get("label", 0)
        if not text:
            continue
        # label==1 or label=="injection" means injection
        if isinstance(label, str):
            relevant = (label.lower() in ("injection", "1", "true"))
        else:
            try:
                relevant = (int(label) == 1)
            except (TypeError, ValueError):
                relevant = False
        entry = make_entry(
            selftext=text,
            source_dataset=source,
            permalink=url,
            subreddit="HuggingFace",
            relevant=relevant,
            taxonomy_category="Indirect & Prompt Injection",
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_anthropic_hh_rlhf() -> list:
    """Anthropic/hh-rlhf harmlessness split (MIT) — first 500 entries only"""
    source = "Anthropic/hh-rlhf"
    url = "https://huggingface.co/datasets/Anthropic/hh-rlhf/resolve/main/harmless-base/train.jsonl.gz"
    print(f"  Fetching {source} (limit 500)...")
    records = fetch_jsonl_gz(url, limit=500)
    if records is None:
        return []
    entries = []
    for rec in records:
        # Extract the first human turn from `rejected` (the more harmful version)
        rejected = rec.get("rejected", "") or ""
        # Conversation format: "\n\nHuman: ...\n\nAssistant: ..."
        human_turn = ""
        if "\n\nHuman:" in rejected:
            parts = rejected.split("\n\nHuman:")
            if len(parts) > 1:
                turn = parts[1].split("\n\nAssistant:")[0].strip()
                human_turn = turn
        if not human_turn:
            # Try chosen as fallback
            chosen = rec.get("chosen", "") or ""
            if "\n\nHuman:" in chosen:
                parts = chosen.split("\n\nHuman:")
                if len(parts) > 1:
                    turn = parts[1].split("\n\nAssistant:")[0].strip()
                    human_turn = turn
        if not human_turn:
            continue
        entry = make_entry(
            selftext=human_turn,
            source_dataset=source,
            permalink=url,
            subreddit="HuggingFace",
            relevant=True,
            taxonomy_category="Defense & Red-team Research",
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_cais_wmdp() -> list:
    """cais/wmdp (MIT) — first 200 entries across cyber/bio/chem splits"""
    source = "cais/wmdp"
    # Dataset is split into wmdp-cyber, wmdp-bio, wmdp-chem with test parquet files
    urls = [
        "https://huggingface.co/datasets/cais/wmdp/resolve/main/wmdp-cyber/test-00000-of-00001.parquet",
        "https://huggingface.co/datasets/cais/wmdp/resolve/main/wmdp-bio/test-00000-of-00001.parquet",
        "https://huggingface.co/datasets/cais/wmdp/resolve/main/wmdp-chem/test-00000-of-00001.parquet",
    ]
    print(f"  Fetching {source} (limit 200 total)...")
    entries = []
    count = 0
    for url in urls:
        if count >= 200:
            break
        df = fetch_parquet(url)
        if df is None:
            continue
        for _, row in df.iterrows():
            if count >= 200:
                break
            question = str(row.get("question", "") or "").strip()
            if not question:
                continue
            entry = make_entry(
                selftext=question,
                source_dataset=source,
                permalink=url,
                subreddit="HuggingFace",
                relevant=True,
                taxonomy_category="Defense & Red-team Research",
            )
            if entry:
                entries.append(entry)
                count += 1
    return entries


def fetch_verazuo_jailbreak_llms() -> list:
    """verazuo/jailbreak_llms (MIT) — most valuable source"""
    source = "verazuo/jailbreak_llms"
    # Correct paths: data is under data/prompts/, not data/ directly
    urls = [
        "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_12_25.csv",
        "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_05_07.csv",
    ]
    print(f"  Fetching {source}...")
    all_entries = []
    seen_prompts: set = set()
    for url in urls:
        text = fetch_csv_text(url)
        if text is None:
            continue
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            # These files contain only jailbreak prompts
            prompt = (row.get("prompt") or row.get("Prompt") or "").strip()
            if not prompt or prompt in seen_prompts:
                continue
            seen_prompts.add(prompt)
            entry = make_entry(
                selftext=prompt,
                source_dataset=source,
                permalink=url,
                subreddit="GitHub",
                relevant=True,
            )
            if entry:
                all_entries.append(entry)
    return all_entries


def fetch_giskard_prompt_injections() -> list:
    """Giskard-AI/prompt-injections (MIT)"""
    source = "Giskard-AI/prompt-injections"
    url = "https://raw.githubusercontent.com/Giskard-AI/prompt-injections/main/prompt_injections.csv"
    print(f"  Fetching {source}...")
    text = fetch_csv_text(url)
    if text is None:
        return []
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    fieldnames = reader.fieldnames or []
    # Try common column names
    prompt_col = None
    for col in ["prompt", "text", "input", "injection", "content"]:
        if col in fieldnames:
            prompt_col = col
            break
    if prompt_col is None and fieldnames:
        prompt_col = fieldnames[0]
    for row in reader:
        prompt = (row.get(prompt_col) or "").strip() if prompt_col else ""
        if not prompt:
            continue
        entry = make_entry(
            selftext=prompt,
            source_dataset=source,
            permalink=url,
            subreddit="GitHub",
            relevant=True,
            taxonomy_category="Indirect & Prompt Injection",
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_harmbench_behaviors() -> list:
    """centerforaisafety/HarmBench (MIT)"""
    source = "centerforaisafety/HarmBench"
    url = "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
    print(f"  Fetching {source}...")
    text = fetch_csv_text(url)
    if text is None:
        return []
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        behavior = (row.get("Behavior") or row.get("behavior") or "").strip()
        sem_cat = (row.get("SemanticCategory") or row.get("Category") or "").strip()
        if not behavior:
            continue
        # Map SemanticCategory to taxonomy
        cat_low = sem_cat.lower()
        if any(x in cat_low for x in ["chemical", "biological", "weapon", "nuclear", "radiological"]):
            tax = "Defense & Red-team Research"
        elif any(x in cat_low for x in ["cyber", "malware", "hack"]):
            tax = "Instruction Hierarchy Attacks"
        elif any(x in cat_low for x in ["misinformation", "disinformation", "fraud"]):
            tax = "Role & Persona Manipulation"
        else:
            tax = infer_taxonomy(behavior, source)
        entry = make_entry(
            selftext=behavior,
            source_dataset=source,
            permalink=url,
            subreddit="GitHub",
            relevant=True,
            title=behavior[:80],
            taxonomy_category=tax,
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_strongreject() -> list:
    """alexandrasouly/strongreject (MIT)"""
    source = "alexandrasouly/strongreject"
    url = "https://raw.githubusercontent.com/alexandrasouly/strongreject/main/strongreject_dataset/strongreject_dataset.csv"
    print(f"  Fetching {source}...")
    text = fetch_csv_text(url)
    if text is None:
        return []
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        prompt = (row.get("forbidden_prompt") or row.get("prompt") or row.get("text") or "").strip()
        category = (row.get("category") or "").strip()
        if not prompt:
            continue
        tax = infer_taxonomy(prompt, source)
        entry = make_entry(
            selftext=prompt,
            source_dataset=source,
            permalink=url,
            subreddit="GitHub",
            relevant=True,
            taxonomy_category=tax,
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_llm_attacks_advbench() -> list:
    """llm-attacks/llm-attacks AdvBench (MIT)"""
    source = "llm-attacks/llm-attacks"
    url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    print(f"  Fetching {source}...")
    text = fetch_csv_text(url)
    if text is None:
        return []
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        goal = (row.get("goal") or row.get("Goal") or "").strip()
        if not goal:
            continue
        entry = make_entry(
            selftext=goal,
            source_dataset=source,
            permalink=url,
            subreddit="GitHub",
            relevant=True,
            taxonomy_category="Instruction Hierarchy Attacks",
        )
        if entry:
            entries.append(entry)
    return entries


def fetch_latent_jailbreak() -> list:
    """qiuhuachuan/latent-jailbreak (MIT)"""
    source = "qiuhuachuan/latent-jailbreak"
    # Prompts are under prompts/ as JSON files (template/llm/composition based)
    urls = [
        "https://raw.githubusercontent.com/qiuhuachuan/latent-jailbreak/main/prompts/template_based.json",
        "https://raw.githubusercontent.com/qiuhuachuan/latent-jailbreak/main/prompts/llm_based.json",
        "https://raw.githubusercontent.com/qiuhuachuan/latent-jailbreak/main/prompts/composition_based.json",
    ]
    print(f"  Fetching {source}...")
    entries = []
    for url in urls:
        data = fetch_bytes(url)
        if data is None:
            continue
        try:
            records = json.loads(data.decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"    [WARN] Failed to parse JSON from {url}: {e}")
            continue
        if not isinstance(records, list):
            continue
        for rec in records:
            if not isinstance(rec, dict):
                continue
            instruction = (
                rec.get("prompt") or
                rec.get("instruction") or
                rec.get("text") or
                ""
            ).strip()
            if not instruction:
                continue
            entry = make_entry(
                selftext=instruction,
                source_dataset=source,
                permalink=url,
                subreddit="GitHub",
                relevant=True,
                taxonomy_category="Indirect & Prompt Injection",
            )
            if entry:
                entries.append(entry)
    if not entries:
        print(f"    [WARN] Could not fetch any entries from {source}")
    return entries


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

SOURCE_FETCHERS = [
    ("deepset/prompt-injections",                   fetch_deepset_prompt_injections),
    ("jackhhao/jailbreak-classification",           fetch_jackhhao_jailbreak_classification),
    ("walledai/JailbreakHub",                       fetch_walledai_jailbreakhub),
    ("TrustAIRLab/in-the-wild-jailbreak-prompts",  fetch_trustairlab_in_the_wild),
    ("JailbreakBench/JBB-Behaviors",               fetch_jailbreakbench_jbb_behaviors),
    ("Lakera/gandalf_ignore_instructions",          fetch_lakera_gandalf),
    ("Anthropic/hh-rlhf",                          fetch_anthropic_hh_rlhf),
    ("cais/wmdp",                                  fetch_cais_wmdp),
    ("verazuo/jailbreak_llms",                     fetch_verazuo_jailbreak_llms),
    ("Giskard-AI/prompt-injections",               fetch_giskard_prompt_injections),
    ("centerforaisafety/HarmBench",                fetch_harmbench_behaviors),
    ("alexandrasouly/strongreject",                fetch_strongreject),
    ("llm-attacks/llm-attacks",                    fetch_llm_attacks_advbench),
    ("qiuhuachuan/latent-jailbreak",               fetch_latent_jailbreak),
]


def load_existing_db() -> tuple[list, set]:
    """Load master_db.json and return (entries, set_of_content_hashes)."""
    if not os.path.exists(MASTER_DB_PATH):
        os.makedirs(DATA_DIR, exist_ok=True)
        return [], set()
    try:
        with open(MASTER_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Collect existing hashes — use id field (which is the content hash for new entries)
        # Also hash existing selftext for dedup against older entries that use Reddit IDs
        hashes = set()
        for entry in data:
            hashes.add(entry.get("id", ""))
            st = entry.get("selftext", "")
            if st:
                hashes.add(content_hash(st))
        return data, hashes
    except Exception as e:
        print(f"[WARN] Could not load existing master_db.json: {e}")
        return [], set()


def save_db(entries: list) -> None:
    """Save entries list to master_db.json."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(MASTER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


def print_summary_table(results: list) -> None:
    """Print a formatted summary table."""
    print()
    print("=" * 65)
    print(f"{'Source':<42} {'Fetched':>7} {'New':>7} {'Skipped':>7}")
    print("-" * 65)
    total_fetched = total_new = total_skipped = 0
    for source, fetched, new_added, skipped in results:
        print(f"{source:<42} {fetched:>7} {new_added:>7} {skipped:>7}")
        total_fetched += fetched
        total_new += new_added
        total_skipped += skipped
    print("-" * 65)
    print(f"{'TOTAL':<42} {total_fetched:>7} {total_new:>7} {total_skipped:>7}")
    print("=" * 65)
    print()


def main():
    print("=" * 65)
    print("fetch_datasets.py — Tier 1 AI Security Dataset Fetcher")
    print(f"Started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 65)
    print()

    # Load existing DB
    print(f"Loading existing master_db from: {MASTER_DB_PATH}")
    existing_entries, existing_hashes = load_existing_db()
    print(f"  Existing entries: {len(existing_entries)}")
    print(f"  Existing content hashes: {len(existing_hashes)}")
    print()

    all_new_entries = []
    summary_rows = []

    for source_name, fetcher_fn in SOURCE_FETCHERS:
        try:
            raw_entries = fetcher_fn()
        except Exception as e:
            print(f"  [ERROR] {source_name}: {e}")
            raw_entries = []

        fetched = len(raw_entries)
        new_added = 0
        skipped = 0

        for entry in raw_entries:
            if entry is None:
                continue
            h = entry.get("id", "")
            st = entry.get("selftext", "")
            st_hash = content_hash(st) if st else ""

            # ---- STRICT ADVERSARIAL GATE ----
            # Apply the same gate used in refilter_db.py to every incoming
            # entry so that SEO templates, marketing copy, and benign prompts
            # are never added to the DB on future ingestion runs.
            if not is_adversarial(st):
                entry["relevant"] = False
                # Still add to DB (for completeness) but mark as non-relevant
                # so the dashboard filters it out.
            else:
                entry["relevant"] = True

            # Dedup check: id OR selftext hash already in existing_hashes
            if h in existing_hashes or st_hash in existing_hashes:
                skipped += 1
                continue
            # Also dedup within this run's new entries
            if h in {e["id"] for e in all_new_entries}:
                skipped += 1
                continue
            all_new_entries.append(entry)
            existing_hashes.add(h)
            if st_hash:
                existing_hashes.add(st_hash)
            new_added += 1

        summary_rows.append((source_name, fetched, new_added, skipped))
        print(f"    -> {source_name}: fetched={fetched}, new={new_added}, skipped={skipped}")

    # Append new entries to existing DB
    final_db = existing_entries + all_new_entries
    print()
    print(f"Saving {len(final_db)} total entries ({len(all_new_entries)} new) to master_db.json...")
    save_db(final_db)
    print("  Saved successfully.")

    print_summary_table(summary_rows)
    print(f"Total entries in master_db.json: {len(final_db)}")
    print()


if __name__ == "__main__":
    main()
