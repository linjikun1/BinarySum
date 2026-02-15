# -*- coding: utf-8 -*-
"""
CFG + CG in one script, with logic fully separated.

Outputs:
- CFG: data/x64_O2/<project>/<binary>_cfgdata.json
- CG : data/x64_O2/<project>/<binary>_cgdata.json
"""

import idaapi
import idautils
import idc
import ida_auto
import json
import os
import re
from collections import defaultdict, Counter

# -----------------------------
# Global output dirs
# -----------------------------
bin_dir = os.environ.get("bin_dir")
arch_opt = os.environ.get("arch_opt")
OUTPUT_ROOT = f"{bin_dir}/{arch_opt}"

CFG_OUTPUT_ROOT = OUTPUT_ROOT
CG_OUTPUT_ROOT = OUTPUT_ROOT

for _plugin in ("hexrays", "hexx64"):
    try:
        idaapi.load_plugin(_plugin)
    except Exception:
        pass

# -----------------------------
# Common helpers
# -----------------------------
def wait_auto():
    try:
        idaapi.auto_wait()
    except Exception:
        try:
            import ida_auto
            ida_auto.auto_wait()
        except Exception:
            pass


def get_decompiled_code(func_addr):
    try:
        decompiled_code = idaapi.decompile(func_addr)
        return str(decompiled_code)
    except Exception as e:
        print(f"Failed to decompile function at {hex(func_addr)}: {e}")
        return None


def word_count(code: str) -> int:
    tokens = re.findall(r"\w+|[^\s\w]", code)
    return len(tokens)


# -----------------------------
# (Optional) Supplement missing funcs for better CFG/CG
# -----------------------------
def _collect_blocks_and_jump_targets():
    all_block_starts = set()
    jump_targets = set()

    for f_ea in idautils.Functions():
        f = idaapi.get_func(f_ea)
        if not f:
            continue
        try:
            fc = idaapi.FlowChart(f)
        except Exception:
            continue

        for b in fc:
            bstart, bend = b.start_ea, b.end_ea
            all_block_starts.add(bstart)

            last = idc.prev_head(bend)
            if last != idc.BADADDR:
                for tgt in idautils.CodeRefsFrom(last, 0):
                    jump_targets.add(tgt)

            for ea in idautils.Heads(bstart, bend):
                if idc.is_jmp_insn(ea):
                    for tgt in idautils.CodeRefsFrom(ea, 0):
                        jump_targets.add(tgt)

    return all_block_starts, jump_targets


def supplement_missing_functions():
    all_block_starts, jump_targets = _collect_blocks_and_jump_targets()
    missing = set(t for t in jump_targets if t not in all_block_starts)

    supplemented = set()
    for ea in missing:
        flags = idc.get_full_flags(ea)
        if not idc.is_code(flags):
            try:
                idc.create_insn(ea)
            except Exception:
                pass

        if idaapi.get_func(ea) is None and idc.is_code(idc.get_full_flags(ea)):
            ok = idaapi.add_func(ea)
            if ok:
                supplemented.add(ea)
                print(f"[INFO] Created function at 0x{ea:x}")
            else:
                print(f"[WARN] Failed to create function at 0x{ea:x}")

    return supplemented


# ============================================================
# CFG logic (independent)
# ============================================================
def build_cfg(func):
    cfg = {}
    try:
        fc = idaapi.FlowChart(func)
    except Exception as e:
        print(f"FlowChart failed for {idc.get_func_name(func.start_ea)}: {e}")
        return cfg

    for block in fc:
        block_data = {
            "start_ea": block.start_ea,
            "end_ea": block.end_ea,
            "instructions": [],
            "successors": [succ.start_ea for succ in block.succs()],
        }
        for head in idautils.Heads(block.start_ea, block.end_ea):
            disasm = idc.GetDisasm(head)
            block_data["instructions"].append({
                "address": head,
                "disassembly": disasm
            })
        cfg[block.start_ea] = block_data

    return cfg


def extract_cfg_data():
    """
    Extract CFG for all decompilable functions.
    NOTE: This function does NOT apply CG filters.
    """
    cfg_result = {}

    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func or (func.end_ea - func.start_ea) <= 0:
            continue

        func_name = idc.get_func_name(func_ea)
        code = get_decompiled_code(func_ea)
        if not code:
            continue

        cfg_result[func_name] = {
            "decompiled_code": code,
            "cfg": build_cfg(func)
        }

    return cfg_result


# ============================================================
# CG logic (independent)
# ============================================================
import ida_hexrays
import ida_nalt
import ida_funcs

# Collect imported EAs once
imported_eas = set()
try:
    mod_qty = ida_nalt.get_import_module_qty()
    for mod_idx in range(mod_qty):
        def _cb(ea, name, ordinal):
            imported_eas.add(ea)
            return True
        ida_nalt.enum_import_names(mod_idx, _cb)
except Exception:
    pass

IMPORT_SEG_NAMES = {
    ".plt", ".plt.sec", ".got", ".got.plt",
    ".idata", ".idata$5", ".idata$6", ".idata$7",
    "__IMPORT", "__imp", "__plt"
}


def is_external_api(func_ea: int) -> bool:
    if func_ea in imported_eas:
        return True
    seg_name = idc.get_segm_name(func_ea)
    if seg_name and seg_name.lower() in IMPORT_SEG_NAMES:
        return True
    try:
        decomp = str(ida_hexrays.decompile(func_ea))
    except Exception:
        return True
    if not decomp.strip():
        return True
    if idc.print_insn_mnem(func_ea).lower() == "jmp":
        return True
    return False


def is_noise_code(code: str, func_ea: int) -> bool:
    if code.startswith("// attributes: thunk"):
        return True

    cleaned = re.sub(r"//.*?$", "", code, flags=re.M).strip()
    m_body = re.search(r"\{(.*)\}", cleaned, flags=re.S)
    if m_body:
        body = m_body.group(1).strip()
        stmts = [s.strip() for s in body.split(';') if s.strip()]
        if len(stmts) == 1:
            if re.match(r"^(return\s+[^;]+|JUMPOUT\(.*\)|longjmp\(.*\)|setjmp\(.*\)|goto\s+\w+)$", stmts[0]):
                return True

    if re.fullmatch(r".*\{\s*(;|return;)?\s*\}", cleaned, flags=re.S):
        return True

    func = idaapi.get_func(func_ea)
    if func and (func.end_ea - func.start_ea) <= 4:
        if idc.print_insn_mnem(func.start_ea).lower() in {"ret", "retn"}:
            return True

    return False


def extract_thunk_target(code: str):
    m = re.search(r"return\s+([A-Za-z_]\w*)\s*\(", code)
    return m.group(1) if m else None


def resolve_real_target(ea: int, max_depth: int = 5) -> int:
    """
    Follow trivial thunks/wrappers to the real function.
    Bugfix: is_noise_code must be evaluated on current function EA (cur_ea), not original EA.
    """
    visited = set()
    depth = 0
    cur_ea = ea
    while depth < max_depth and cur_ea not in visited:
        visited.add(cur_ea)
        func = idaapi.get_func(cur_ea)
        if not func:
            break
        try:
            code = str(ida_hexrays.decompile(func.start_ea))
        except Exception:
            break

        if not is_noise_code(code, cur_ea):
            break

        tgt_name = extract_thunk_target(code)
        if not tgt_name:
            break
        next_ea = idc.get_name_ea(idc.BADADDR, tgt_name)
        if next_ea == idc.BADADDR:
            break
        cur_ea = next_ea
        depth += 1
    return cur_ea


def _iter_call_targets(call_insn_ea: int):
    """
    Keep original behavior (operand_value) but add xref fallback.
    This avoids 'cg_result always empty' on binaries with reloc/PLT/odd calls.
    """
    # 1) original: operand value
    op_type = idc.get_operand_type(call_insn_ea, 0)
    if op_type in (idc.o_near, idc.o_far, idc.o_mem):
        opnd_ea = idc.get_operand_value(call_insn_ea, 0)
        if opnd_ea != idc.BADADDR:
            yield opnd_ea

    # 2) fallback: direct xrefs (for 'call sub_xxx' cases)
    for tgt in idautils.CodeRefsFrom(call_insn_ea, 0):
        yield tgt

import ida_idp
def process_function(func_ea: int):
    func = idaapi.get_func(func_ea)
    if not func:
        return
    caller_name = idaapi.get_func_name(func_ea)

    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(head).lower()
        if not (mnem.startswith("call") or mnem.startswith("bl")):
            continue

        for opnd_ea in _iter_call_targets(head):
            callee_func = idaapi.get_func(opnd_ea)
            if not callee_func:
                continue

            real_ea = resolve_real_target(callee_func.start_ea)
            real_name = idaapi.get_func_name(real_ea)
            if not real_name or is_external_api(real_ea):
                continue

            call_graph[caller_name].add(real_name)
            call_counter[caller_name][real_name] += 1

def collect_cg_candidates():
    """
    Collect func_info + noise_set for CG only.
    IMPORTANT: Do NOT drop functions just because they start with // attributes:
    Original gen_cg.py only treats 'thunk' as noise.
    """
    func_info = {}
    noise_set = set()

    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func or (func.end_ea - func.start_ea) <= 0:
            continue

        func_name = idc.get_func_name(func_ea)

        try:
            code_obj = ida_hexrays.decompile(func_ea)
        except Exception:
            continue
        if not code_obj:
            continue
        code = str(code_obj)
        if not code:
            continue

        if not (30 < word_count(code) < 9192):
            continue

        func_info[func_name] = [func_ea, code]
        if is_noise_code(code, func_ea):
            noise_set.add(func_name)

    return func_info, noise_set



call_graph = defaultdict(set)
call_counter = defaultdict(Counter)

def extract_cg_data(project_name: str):
    """
    Build CG result list (same schema as your merged script).
    """
    ida_auto.auto_wait()
    # func_info, noise_set = collect_cg_candidates()

    # for func_name, (ea, _) in func_info.items():
    #     if func_name in noise_set:
    #         continue
    #     process_function(ea, call_graph, call_counter)
    noise_set = set()
    func_info = {}
    for func_ea in idautils.Functions():
        code = ida_hexrays.decompile(func_ea)
        if code is None:
            print((f"[-] Failed to decompile function at {hex(func_ea)}: code is None"))
            continue
        code = str(code)
        if not (30 < word_count(code) < 9192):
            continue
        func_name = idaapi.get_func_name(func_ea)
        func_info[func_name] = [func_ea, code]

        if is_noise_code(code, func_ea):
            noise_set.add(func_name)
        else:
            process_function(func_ea)
    callers_map = defaultdict(set)
    for caller, callees in call_graph.items():
        for callee in callees:
            callers_map[callee].add(caller)

    result = []
    for name, (ea, code) in func_info.items():
        if name in noise_set:
            continue

        all_callees = call_counter[name]
        all_callers = {caller: call_counter[caller][name] for caller in callers_map.get(name, [])}
        if not all_callees and not all_callers:
            continue

        top_callees = list(all_callees.items())
        top_callers = list(all_callers.items())

        callees            = {k : func_info[k][1] for k, _ in top_callees if k in func_info}
        callees_call_count = {k: v for k, v in top_callees}

        callers            = {k : func_info[k][1] for k, _ in top_callers if k in func_info}
        callers_call_count = {k: v for k, v in top_callers}

        if callees == {} and callers == {}:
            continue

        result.append({
            "project_name": project_name,
            "function_addr": ea,
            "strip_function_name": name,
            "strip_decompiled_code": code,
            "callers": callers,
            "callees": callees,
            "callers_call_count": callers_call_count,
            "callees_call_count": callees_call_count
        })
    return result


# ============================================================
# Output
# ============================================================
def write_outputs(cfg_result, cg_result, cfg_output_dir, cg_output_dir, binary_name):
    os.makedirs(cfg_output_dir, exist_ok=True)
    cfg_file = os.path.join(cfg_output_dir, f"{binary_name}_cfgdata.json")
    with open(cfg_file, "w", encoding="utf-8") as f:
        json.dump(cfg_result, f, indent=4, ensure_ascii=False)
    print(f"[*] 写入 CFG: {cfg_file} (函数数: {len(cfg_result)})")

    os.makedirs(cg_output_dir, exist_ok=True)
    cg_file = os.path.join(cg_output_dir, f"{binary_name}_cgdata.json")
    with open(cg_file, "w", encoding="utf-8") as f:
        json.dump(cg_result, f, ensure_ascii=False, indent=2)
    print(f"[*] 写入 CG : {cg_file} (非噪声节点数: {len(cg_result)})")


# ============================================================
# Main
# ============================================================
def main(project_name: str, binary_name: str, cfg_output_dir: str, cg_output_dir: str):
    wait_auto()

    # Optional supplement stage (helps both CFG/CG)
    try:
        supplemented = supplement_missing_functions()
        if supplemented:
            wait_auto()
            print(f"[INFO] supplemented functions: {len(supplemented)}")
    except Exception as e:
        print(f"[WARN] supplement stage failed: {e}")

    # --- fully separated extractions ---
    cg_result = extract_cg_data(project_name)
    # cfg_result = extract_cfg_data()
    cfg_result = []
    # print(f"cfg_result: {len(cfg_result)}")
    print(f"cg_result: {len(cg_result)}")

    write_outputs(cfg_result, cg_result, cfg_output_dir, cg_output_dir, binary_name)


if __name__ == "__main__":
    binary_path = idc.get_input_file_path()
    binary_name = os.path.basename(binary_path)
    project_name = os.path.basename(os.path.dirname(binary_path))

    cfg_output_dir = os.path.join(CFG_OUTPUT_ROOT, project_name)
    cg_output_dir = os.path.join(CG_OUTPUT_ROOT, project_name)

    main(project_name, binary_name, cfg_output_dir, cg_output_dir)
    idaapi.qexit(0)
