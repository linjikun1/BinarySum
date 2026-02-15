import time
import os
import sys
from typing import Set
from analysis.prog_model import Instruction, BasicBlock, Function, ReachDefinitionAnalysis, PostDominatorAnalysis, ControlDependenceAnalysis
import networkx as nx
import json

class ExprLangAnalyzer:
    
    def __init__(self, cfg:nx.classes.DiGraph):        
        self.func = Function(cfg)
        self.reach_def = ReachDefinitionAnalysis(self.func)
        self.reach_def.run()
        self.post_dominator = PostDominatorAnalysis(self.func)
        self.post_dominator.run()
        self.control_dependence = ControlDependenceAnalysis(self.func, self.post_dominator)
        self.control_dependence.run()
        self.addr2our_bb = self.func.addr2our_bb
        self.dep = []
        # Note: we need to precompute intra-block dependencies
        # because we might recurse into a block and we need to know
        # what the intra-block dependencies are for that block
        self.instr_to_intra_block_dep = {}
        for bb_addr in sorted(self.addr2our_bb.keys()):
          intra_block_dep = {}
          bb = self.addr2our_bb[bb_addr]
          for instr in bb.instrs:
              self.instr_to_intra_block_dep[instr.id] = dict(intra_block_dep)                 
              for current_def in instr.defs:
                  intra_block_dep[current_def] = instr
        for bb_addr in sorted(self.addr2our_bb.keys()):
            self._print_dep_for_bb(self.addr2our_bb[bb_addr])
        
    # ---------- 通用工具 ----------
    def _distinct_deps(self):
        return sorted(set(self.dep), key=lambda x: x[0])

    def _iter_instrs(self):
        for bb_addr in sorted(self.addr2our_bb.keys()):
            for instr in self.addr2our_bb[bb_addr].instrs:
                yield instr

    def _build_instrs_and_deps(self):
        instr_strs = [
            (instr.id, instr.code.split(';')[0]) for instr in self._iter_instrs()
        ]
        return instr_strs, [(dst, src) for dst, src in self._distinct_deps()]

    def _load_normalized_code(self, metadata):
        pos = metadata['binary_name'].find('_extract')
        norm_asm_file = metadata['binary_name'][:pos] + '.normalized_code.json'
        norm_asm_path = os.path.join(metadata['project_path'], norm_asm_file)
        with open(norm_asm_path, 'r') as f:
            data = json.load(f)
        for addr, body in data.items():
            data[addr] = [instr.replace('_', ' ') for instr in body]
        return data

    def print_func_to_jsonl_for_ProRec(self, fout, metadata={}):
        # 原始 ProRec
        instr_strs, deps_strs = self._build_instrs_and_deps()

        data_out = {
            'project_name': os.path.basename(metadata['project_path']),
            'function_addr': metadata['function_addr'],
            'strip_function_name': metadata['strip_function_name'],
            'strip_decompiled_code': metadata['strip_decompiled_code'],
            'code': instr_strs,
            'data_dep': deps_strs
        }
        fout.write((json.dumps(data_out) + '\n').encode('utf-8'))
        fout.flush()

    def print_func_to_jsonl(self, fout, metadata={}, metadata_for_ProRec={}):
        # 兼容现有工作
        instr_strs, deps_strs = self._build_instrs_and_deps()

        try:
            data = self._load_normalized_code(metadata)
        except Exception as e:
            print(f"Load normalized code failed: {e}")
            return

        norm_strs = []
        for instr_id, _ in instr_strs:
            try:
                norm_instr_str = data[str(metadata['function_addr'])][instr_id].replace(' ', '_')
            except Exception:
                # print(metadata['function_addr'])
                # print("Error: ", len(data.get(str(metadata['function_addr']), [])), instr_id)
                return
            norm_strs.append((instr_id, norm_instr_str.replace(',', '')))
        cfg = self.get_norm_cfg(norm_strs, deps_strs)
        
        data_out = {
            'project_name': os.path.basename(metadata['project_path']),
            'function_addr': metadata['function_addr'],
            'strip_function_name': metadata['strip_function_name'],
            'strip_decompiled_code': metadata['strip_decompiled_code'],
            'function_name': metadata['function_name'],
            'decompiled_code': metadata['decompiled_code'],
            'asm_code': data[str(metadata['function_addr'])],
            'cfg': cfg,
            'data_for_ProRec': {
                'strip_function_name': metadata_for_ProRec['strip_function_name'],
                'strip_decompiled_code': metadata_for_ProRec['strip_decompiled_code'],
                'code': instr_strs,
                'data_dep': deps_strs
            }
        }

        fout.write((json.dumps(data_out) + '\n').encode('utf-8'))
        fout.flush()
        
    def get_norm_cfg(self, norm_strs, deps_strs):
        instr_map = {instr_id: instr_str for instr_id, instr_str in norm_strs}

        data_dep_sorted = sorted(deps_strs, key=lambda x: x[1])

        edges = [
            (instr_map[src_id], instr_map[dst_id]) for dst_id, src_id in data_dep_sorted
        ]

        dep_index = []
        for _, src_id in data_dep_sorted:
            if src_id not in dep_index:
                dep_index.append(src_id)

        for dst_id, _ in data_dep_sorted:
            if dst_id not in dep_index:
                dep_index.append(dst_id)

        nodes = [instr_map[dep_id] for dep_id in dep_index]

        edge_index = [
            [nodes.index(instr_map[src_id]) for _, src_id in data_dep_sorted ], 
            [nodes.index(instr_map[dst_id]) for dst_id, _ in data_dep_sorted ]
        ]

        cfg = {
            'nodes': nodes,
            'edges': str(edges),
            'edge_index': edge_index
        }
        
        return cfg

    def _print_dep_for_instr(self, visited : Set, indent: int, instr:Instruction):
        intra_block_dep = self.instr_to_intra_block_dep[instr.id]
        inter_block_dep = self.reach_def.bb_in[instr.basic_block.addr]
        INDENT = '   '
        current_indent = INDENT * indent
        if instr.id in visited:
            # print(current_indent, end='')
            # print("Cyclic dependency detected, skipping instr %d" % instr.id)
            return
        visited.add(instr.id)
        # print(current_indent, end='')
        # print('instr: %d: %s' % (instr.id, instr))
        current_instr_id = instr.id
        deps = []
        for use in instr.uses:
            # print(current_indent, end='')
            # print(' ;use: %s' % use)
            # print(current_indent, end='  ')
            if use in intra_block_dep:
                self.dep.append((current_instr_id, intra_block_dep[use].id))
                # print(';intra_block_dep: %d' % intra_block_dep[use].id)
                # self._print_dep_for_instr(visited, indent+1, intra_block_dep[use])
            elif use in inter_block_dep:
                # print(';inter_block_dep:[', end=' ')
                for def_instr in inter_block_dep[use]:
                    self.dep.append((current_instr_id, def_instr.id))
                    # print('%d,' % def_instr.id, end=' ')
                # print(']', end=' ')                
                # if len(inter_block_dep[use]) > 1:
                #     print("**phi node here**")
                # else:
                #     print()
                # for def_instr in inter_block_dep[use]:
                #     self._print_dep_for_instr(visited, indent+1, def_instr)
            else:
                # print(';definition may be outside of current function')
                pass
        visited.remove(instr.id)


                    
            

    # used for dbg
    def _print_dep_for_bb(self, bb:BasicBlock):
        def_in = self.reach_def.bb_in[bb.addr]
        # print()
        # print(";BB: %x" % bb.addr)
        # for k,v in def_in.items():
        #     print(";var: %s, def: [" % k, end='')
        #     for instr in v:
        #         print("%d, " % instr.id, end='')
        #     print("]")

        for instr in bb.instrs:
            self._print_dep_for_instr(set(), 0, instr)