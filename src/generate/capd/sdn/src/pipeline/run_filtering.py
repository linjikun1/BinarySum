import json
from tqdm import tqdm
from src.core.filter_client import CodeFilter

def extract_probed_code(probed_sources):
    strip_len = len('<asm_token>\n')
    processed_probed_sources = []
    for ps in probed_sources:
        asm_idx = ps.find('<asm_token>')
        if asm_idx == -1:
            processed_probed_sources.append(ps)
        else:
            pps = ps[asm_idx + strip_len:]
            processed_probed_sources.append(pps)
    return processed_probed_sources

def run_filtering_pipeline(input_file, output_file, config):
    print(f"Loading data from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            probed_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file {input_file} not found.")
        return

    code_filter = CodeFilter(
        api_key=config['api_key'], 
        model_name=config['model_name'], 
        base_url=config['base_url']
    )

    stats = {
        "total_candidates": 0,
        "strong": 0,
        "backup": 0,
        "uncertain": 0,
        "junk": 0,
        "processed_items": 0
    }

    for item in tqdm(probed_data, total=len(probed_data), desc="Filtering Candidates"):
        if 'codeinfo' not in item or 'decompiled_code' not in item['codeinfo']:
            code = item.get('strip_decompiled_code', "") or item.get('decompiled_code', "")
        else:
            code = item['codeinfo']['decompiled_code']
            
        if not code:
            continue
            
        raw_probed_srcs = extract_probed_code(item.get('probed_sources', []))
        stats["total_candidates"] += len(raw_probed_srcs)

        if not raw_probed_srcs:
            stage1_survivors, stage1_junk = [], []
        else:
            stage1_survivors, stage1_junk = code_filter.filter_first(raw_probed_srcs)
        
        stats["junk"] += len(stage1_junk)

        if not stage1_survivors:
             s2_result = {"has_strong_features": False, "results": []}
        else:
             s2_result = code_filter.filter_second(code, stage1_survivors)

        raw_features = s2_result.get('extracted_features', [])
        valid_features = [feat for feat in raw_features if feat in code]
        has_features = len(valid_features) > 0
        extracted_features = valid_features

        r2_details = s2_result.get("results", [])
        r2_map = {res.get("index"): res for res in r2_details if res.get("index") is not None}

        final_strong = []
        final_backup = []
        final_uncertain = []
        final_junk = list(stage1_junk)
        debug_info = []

        if not has_features:
            final_uncertain = list(stage1_survivors)
            stats["uncertain"] += len(final_uncertain)
            debug_info.append("Target Generic: All Stage1-Survivors -> Uncertain")
        else:
            for idx, fragment in enumerate(stage1_survivors):
                r2 = r2_map.get(idx, {"is_source_match": False, "is_domain_match": False})
                is_source = r2.get("is_source_match", False)    
                is_domain = r2.get("is_domain_match", False)
                evidence = r2.get("evidence", "No evidence")

                if is_source:
                    final_strong.append(fragment)
                    stats["strong"] += 1
                    debug_info.append(f"Idx {idx}: Strong ({evidence})")
                elif is_domain:
                    final_backup.append(fragment)
                    stats["backup"] += 1
                    debug_info.append(f"Idx {idx}: Backup ({evidence})")
                else:
                    final_junk.append({"fragment": fragment, "reason": "Unrelated to strong features"})
                    stats["junk"] += 1
                    debug_info.append(f"Idx {idx}: Junk (GT has features but Candidate unrelated)")

        item['has_strong_features'] = has_features
        item['extracted_features'] = extracted_features
        item['filter_strong'] = final_strong
        item['filter_backup'] = final_backup
        item['filter_uncertain'] = final_uncertain
        item['filter_junk'] = final_junk
        item['debug_log'] = debug_info
        
        stats["processed_items"] += 1

    total_filtered = stats["strong"] + stats["backup"] + stats["uncertain"] + stats["junk"]
    print("\n" + "="*40)
    print(f"Filtering Complete.")
    print(f"Items Processed: {stats['processed_items']}")
    print(f"Total Candidates: {stats['total_candidates']}")
    print("-" * 20)
    print(f"Strong Matches: {stats['strong']}")
    print(f"Backup Matches: {stats['backup']}")
    print(f"Uncertain:      {stats['uncertain']}")
    print(f"Junk/Discarded: {stats['junk']}")
    print(f"Check Sum:      {total_filtered} / {stats['total_candidates']}")
    print("="*40)

    print(f"Saving filtered results to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(probed_data, f, indent=4, ensure_ascii=False)
    print("Done.")
