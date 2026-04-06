#!/usr/bin/env python3
"""
Generate augmented reference summaries for all architectures in data/processed/.

Pipeline:
  Step 1 (collect)  : Aggregate dataset.pkl.gz from all arch dirs, dedup by key,
                       output need_to_gen_augref.pkl.gz
  Step 2 (generate) : Call LLM for each item's source_code, output final_ref.pkl.gz
                       Supports resume (skip already-generated entries).
  Step 3 (apply)    : Read final_ref.pkl.gz, rewrite "comment" field in every
                       dataset.pkl.gz and baseline.pkl.gz under processed/.

Key format (shared across all steps):
    "{project_name}::{source_code[:20]}"

Usage:
    python gen_augref.py [--processed-dir PATH] [--work-dir PATH]
                         [--step {all,collect,generate,apply}]
                         [--profile PROFILE]
"""

import argparse
import gzip
import logging
import os
import pickle
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from tqdm import tqdm

# ---------------------------------------------------------------------------
# Path setup – allow importing config.py from src/
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).parent.resolve()
_SRC_DIR = _SCRIPT_DIR.parent
sys.path.insert(0, str(_SRC_DIR))

from config import get_openai_config, get_generation_config

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_DEFAULT_PROCESSED = _SRC_DIR.parent / "data" / "processed"
_DEFAULT_WORK = _SRC_DIR.parent / "data"

SAVE_EVERY = 50        # checkpoint interval (items updated)
MAX_RETRIES = 5
RETRY_BASE_DELAY = 2.0  # exponential back-off base (seconds)


# ===========================================================================
# Helpers
# ===========================================================================

def make_key(item: Dict[str, Any]) -> str:
    """Unique dedup key shared across all three steps."""
    proj = item.get("project_name", "")
    src  = (item.get("source_code") or "")[:20]
    return f"{proj}::{src}"


def load_pkl_gz(path: Path):
    with gzip.open(path, "rb") as f:
        return pickle.load(f)


def dump_pkl_gz(path: Path, obj, compresslevel: int = 5):
    with gzip.open(path, "wb", compresslevel=compresslevel) as f:
        pickle.dump(obj, f)


# ===========================================================================
# Step 1: collect
# ===========================================================================

def step_collect(processed_dir: Path, work_dir: Path) -> Path:
    """
    Scan all <arch>/dataset.pkl.gz under processed_dir.
    Deduplicate by key and write need_to_gen_augref.pkl.gz.
    Returns the output path.
    """
    out_path = work_dir / "need_to_gen_augref.pkl.gz"

    arch_dirs = sorted(
        p for p in processed_dir.iterdir()
        if p.is_dir() and "_" in p.name
    )
    if not arch_dirs:
        raise RuntimeError(f"No arch directories found under {processed_dir}")

    logger.info(f"Found {len(arch_dirs)} arch dirs: {[d.name for d in arch_dirs]}")

    all_items: Dict[str, Dict[str, Any]] = {}

    for arch_dir in arch_dirs:
        dataset_path = arch_dir / "dataset.pkl.gz"
        if not dataset_path.exists():
            logger.warning(f"  [{arch_dir.name}] dataset.pkl.gz not found, skipping.")
            continue

        data: List[Dict[str, Any]] = load_pkl_gz(dataset_path)
        before = len(all_items)

        for item in tqdm(data, desc=f"  [{arch_dir.name}] collecting", leave=False):
            src = item.get("source_code") or ""
            if not src.strip():
                continue  # skip items without source code
            k = make_key(item)
            if k not in all_items:
                all_items[k] = {
                    "project_name"        : item.get("project_name", ""),
                    "strip_function_name" : item.get("strip_function_name", ""),
                    "source_code"         : src,
                    "comment"             : item.get("comment", ""),
                }

        added = len(all_items) - before
        logger.info(f"  [{arch_dir.name}] {len(data)} items → {added} new unique entries (total {len(all_items)})")

    logger.info(f"Total unique entries: {len(all_items)}")
    dump_pkl_gz(out_path, all_items)
    logger.info(f"Saved → {out_path}")
    return out_path


# ===========================================================================
# Step 2: generate
# ===========================================================================

def build_prompt(source_code: str, lang: str = "C") -> str:
    return f"""
You are given a {lang} function.

Here is the function:
```{lang}
{source_code}
```

Your task: generate a concise, one-sentence summary (max 25 words) describing the function's purpose.

Strict requirements:

* Base it on code details; avoid placeholders and generic descriptions.
* DO NOT use uncertain words like "possible", "seems", "likely", "appears", "may", "might", "probably".
* If the code strongly indicates specific behavior (APIs, literals, patterns), be definitive.
* Output ONLY the single sentence summary, no extra text.
""".strip()


def word_count(s: str) -> int:
    return len((s or "").strip().split())


def is_bad_summary(summary: Optional[str]) -> bool:
    if not summary:
        return True
    s = summary.strip()
    if word_count(s) > 30:
        return True
    low = s.lower()
    if low.startswith(("this function", "this code")):
        return True
    if low.startswith(("performs", "handles", "does", "implements")) and word_count(s) <= 6:
        return True
    return False


def call_llm(client, model: str, temperature: float, source_code: str, lang: str = "C") -> str:
    prompt = build_prompt(source_code, lang=lang)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an experienced software engineer and reverse engineer."},
            {"role": "user",   "content": prompt},
        ],
        temperature=temperature,
    )
    return (resp.choices[0].message.content or "").strip()


def generate_reference(client, model: str, temperature: float, source_code: str, lang: str = "C") -> Optional[str]:
    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            s = call_llm(client, model, temperature, source_code, lang=lang)
            if not is_bad_summary(s):
                return s
            # Quality not good enough – one low-temperature retry
            time.sleep(0.2)
            s2 = call_llm(client, model, temperature, source_code, lang=lang)
            if not is_bad_summary(s2):
                return s2
            return s2  # accept even if still bad; avoids infinite loop
        except Exception as e:
            last_err = e
            delay = RETRY_BASE_DELAY * (2 ** attempt)
            logger.warning(
                f"[Retry {attempt + 1}/{MAX_RETRIES}] LLM call failed: "
                f"{type(e).__name__}: {e} | sleep {delay:.1f}s"
            )
            time.sleep(delay)
    logger.error(f"Giving up after {MAX_RETRIES} retries: {last_err}")
    return None


def step_generate(work_dir: Path, profile: str = "gpt") -> Path:
    """
    Read need_to_gen_augref.pkl.gz, call LLM for each item,
    write final_ref.pkl.gz. Supports resume.
    Returns the output path.
    """
    in_path  = work_dir / "need_to_gen_augref.pkl.gz"
    out_path = work_dir / "final_ref.pkl.gz"

    if not in_path.exists():
        raise FileNotFoundError(f"Input not found: {in_path}  (run --step collect first)")

    to_gen: Dict[str, Dict[str, Any]] = load_pkl_gz(in_path)
    logger.info(f"Loaded {len(to_gen)} items from {in_path}")

    # Resume support
    if out_path.exists():
        final_ref: Dict[str, Dict[str, Any]] = load_pkl_gz(out_path)
        logger.info(f"Resuming: {len(final_ref)} already generated items found in {out_path}")
    else:
        final_ref = {}

    # Load LLM config
    openai_cfg = get_openai_config(profile)
    gen_cfg    = get_generation_config("synthesis")  # reuse synthesis temperature
    api_key    = openai_cfg["api_key"]
    base_url   = openai_cfg["base_url"]
    model      = openai_cfg["model_name"]
    temperature = gen_cfg.get("temperature", 0.7)

    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url=base_url)

    keys    = list(to_gen.keys())
    updated = 0
    skipped = 0
    missing_src = 0

    for k in tqdm(keys, desc="Generating references"):
        rec = to_gen[k]

        # Resume: skip already generated
        if k in final_ref and final_ref[k].get("reference"):
            skipped += 1
            continue

        source_code = rec.get("source_code") or ""
        if not source_code.strip():
            missing_src += 1
            final_ref[k] = {**rec, "reference": ""}
            continue

        ref = generate_reference(client, model, temperature, source_code, lang="C")
        if ref is None:
            ref = ""  # keep empty; can be re-run later

        final_ref[k] = {**rec, "reference": ref}
        updated += 1

        if updated % SAVE_EVERY == 0:
            dump_pkl_gz(out_path, final_ref)
            logger.info(
                f"[Checkpoint] {out_path} ({len(final_ref)} records) "
                f"| updated={updated}, skipped={skipped}, missing_src={missing_src}"
            )

    dump_pkl_gz(out_path, final_ref)
    logger.info(f"Done. final_ref saved → {out_path}")
    logger.info(
        f"Stats: updated={updated}, skipped={skipped}, "
        f"missing_src={missing_src}, total_out={len(final_ref)}"
    )
    return out_path


# ===========================================================================
# Step 3: apply
# ===========================================================================

def apply_to_file(pkl_path: Path, ref_dict: Dict[str, str], arch_name: str, file_label: str):
    """Rewrite comment field in a single pkl.gz file using ref_dict."""
    if not pkl_path.exists():
        return

    data: List[Dict[str, Any]] = load_pkl_gz(pkl_path)

    missing = 0
    applied = 0
    for item in data:
        k = make_key(item)
        ref = ref_dict.get(k)
        if ref is None:
            missing += 1
            continue
        item["reference"] = ref
        applied += 1

    dump_pkl_gz(pkl_path, data)
    logger.info(
        f"  [{arch_name}] {file_label}: applied={applied}, missing={missing}/{len(data)}"
    )


def step_apply(processed_dir: Path, work_dir: Path):
    """
    Read final_ref.pkl.gz and rewrite comment in every
    dataset.pkl.gz and baseline.pkl.gz under processed_dir.
    """
    ref_path = work_dir / "final_ref.pkl.gz"
    if not ref_path.exists():
        raise FileNotFoundError(f"final_ref.pkl.gz not found: {ref_path}  (run --step generate first)")

    final_ref: Dict[str, Dict[str, Any]] = load_pkl_gz(ref_path)
    logger.info(f"Loaded {len(final_ref)} reference entries from {ref_path}")

    # Build key -> reference string lookup
    ref_dict: Dict[str, str] = {k: v.get("reference", "") for k, v in final_ref.items()}

    arch_dirs = sorted(
        p for p in processed_dir.iterdir()
        if p.is_dir() and "_" in p.name
    )

    for arch_dir in arch_dirs:
        for fname in ("dataset.pkl.gz", "baseline.pkl.gz"):
            apply_to_file(arch_dir / fname, ref_dict, arch_dir.name, fname)

    logger.info("Apply step complete.")


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate augmented reference summaries for BinarySum datasets."
    )
    parser.add_argument(
        "--processed-dir",
        default=str(_DEFAULT_PROCESSED),
        help=f"Path to data/processed/ (default: {_DEFAULT_PROCESSED})",
    )
    parser.add_argument(
        "--work-dir",
        default=str(_DEFAULT_WORK),
        help=f"Directory for intermediate files (default: {_DEFAULT_WORK})",
    )
    parser.add_argument(
        "--step",
        choices=["all", "collect", "generate", "apply"],
        default="all",
        help="Which step to run (default: all)",
    )
    parser.add_argument(
        "--profile",
        default="gpt",
        help="config.ini OpenAI profile to use for LLM calls (default: gpt)",
    )
    args = parser.parse_args()

    processed_dir = Path(args.processed_dir)
    work_dir      = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    if not processed_dir.exists():
        logger.error(f"processed_dir does not exist: {processed_dir}")
        sys.exit(1)

    step = args.step

    if step in ("all", "collect"):
        logger.info("=== Step 1: collect ===")
        step_collect(processed_dir, work_dir)

    if step in ("all", "generate"):
        logger.info("=== Step 2: generate ===")
        step_generate(work_dir, profile=args.profile)

    if step in ("all", "apply"):
        logger.info("=== Step 3: apply ===")
        step_apply(processed_dir, work_dir)

    logger.info("All done.")


if __name__ == "__main__":
    main()
