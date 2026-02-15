import re
import os
import json
import pickle
import joblib
import idc
import idautils
import idaapi
from collections import namedtuple

def unsigned2signed(number, width):
    if number > 2**(width-1) - 1:
        number = 2 ** width - number
        number = 0 - number
    return number

def match_cplusplus_function_name(full_name):
    method = full_name
    while method and method[-1] != ')':
        if method[-1] != ':':
            method = method[:-1]
        else:
            return ''

    regex_remove_type = re.compile(r'<[^<>]*>')
    while '<' in method and '>' in method:
        for t in regex_remove_type.findall(method):
            method = method.replace(t, '')

    regex_remove_args = re.compile(r'\([^\(\)]*\)')
    while '(' in method and ')' in method:
        for t in regex_remove_args.findall(method):
            method = method.replace(t, '')

    regex_remove_commet = re.compile(r'\[[^\[\]]*\]')
    while '[' in method and ']' in method:
        for t in regex_remove_commet.findall(method):
            method = method.replace(t, '')

    regex_remove_commet2 = re.compile(r'`[^`\']*\'')
    while '`' in method and '\'' in method:
        for t in regex_remove_commet2.findall(method):
            method = method.replace(t, '')

    if '::' in method:
        method = method.split('::')[-1]
        if ' ' in method:
            method = method.split(' ')[0]
    else:
        method = method.split(' ')[-1]

    if len(method) == 0:
        return ''

    while method[-1] == '*':
        method = method[:-1]

    if method[0] == '~':
        method = method[1:]

    return method

def filter_imm(ea, op_idx):
    op_text = idc.print_operand(ea, op_idx)
    normalize_imm = ''.join([c for c in op_text if c.isalnum()])
    if normalize_imm.startswith('offset'):
        return '<OFFSET>'

    try:
        imm = int(op_text[:-1], 16) if op_text.endswith('h') else int(op_text, 16)
    except:
        return '<UNK>'

    if unsigned2signed(imm, cpu_width) > 0:
        return '<POSITIVE>'
    elif unsigned2signed(imm, cpu_width) < 0:
        return '<NEGATIVE>'
    else:
        return '<ZERO>'

def normalize_instruction(insn, plt_funcs_name):
    inst = insn.get_canon_mnem()
    if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
        call_target = idc.print_operand(insn.ea, 0)
        if call_target in plt_funcs_name:
            inst += '_' + '<ECALL>'
        else:
            inst += '_' + '<ICALL>'
        return inst

    for i in range(idaapi.UA_MAXOP):
        op = insn.ops[i]
        if op.type == idaapi.o_void:
            break
        elif op.type == idaapi.o_reg:
            inst += ' ' + idc.print_operand(insn.ea, i)
        elif op.type == idaapi.o_imm:
            inst += ' ' + filter_imm(insn.ea, i)
        elif op.type == idaapi.o_mem:
            inst += ' ' + '<MEM>'
        elif op.type == idaapi.o_phrase:
            inst += ' ' + idc.print_operand(insn.ea, i)
        elif op.type == idaapi.o_displ:
            inst += ' ' + idc.print_operand(insn.ea, i)
        elif op.type == idaapi.o_near:
            inst += ' ' + '<NEAR>'
        elif op.type == idaapi.o_far:
            inst += ' ' + '<FAR>'
        else:
            inst += ' ' + '<UNK>'

        if i < idaapi.UA_MAXOP - 1:
            inst += ','

    if inst.endswith(','):
        inst = inst[:-1]
    inst = inst.replace(' ', '_')
    return inst

InternalMethod = namedtuple('InternalMethod', ['name', 'start_addr', 'end_addr', 'instructions'])

InputFileName = idc.get_input_file_path()
if os.path.exists(f'{InputFileName}.func_names_and_address'):
    idc.qexit(0)
    
cpu_width = 64 if idc.get_idb_path().endswith('.i64') else 32

idaapi.auto_wait()

segment_ranges = {}
for seg_ea in idautils.Segments():
    seg_name = idc.get_segm_name(seg_ea)
    segment_ranges[seg_name] = (seg_ea, idc.get_segm_end(seg_ea))

print("All Segment Names:", list(segment_ranges.keys()))

target_segments = ['.text', '.init.text', '.exit.text']
methods = {}

for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    if not func_name:
        continue

    func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)

    for seg in target_segments:
        if seg in segment_ranges:
            start, end = segment_ranges[seg]
            if start <= func_ea < end:
                methods[func_name] = [func_ea, func_end]
                break

print(len(methods), "functions found in target segments.")
pickle.dump(methods, open('{}.func_names_and_address'.format(InputFileName), 'wb'), protocol=2)

if not os.path.exists(f'{InputFileName}.func_names_and_address') or os.path.exists(f'{InputFileName}.normalized_code.json'):
    idc.qexit(0)

method_dict = joblib.load(f'{InputFileName}.func_names_and_address')
method_dict = {
    f"{v[0]}_{v[1]}": k for k, v in method_dict.items()
}

plt_funcs_name = []
for seg_ea in idautils.Segments():
    name = idc.get_segm_name(seg_ea)
    if name == '.plt':
        for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
            func_name = idc.get_func_name(func_ea).replace('.', '_')
            plt_funcs_name.append(func_name)
        break

methods = {}

for func_ea in idautils.Functions():
    func_start = func_ea
    func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    key = f"{func_start}_{func_end}"
    if key not in method_dict:
        continue

    func_name = method_dict[key]
    instructions = []

    for head in idautils.Heads(func_start, func_end):
        if idc.is_code(idc.get_full_flags(head)):
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, head):
                instructions.append(normalize_instruction(insn, plt_funcs_name))

    methods[func_name] = InternalMethod(name=func_name, start_addr=func_start, end_addr=func_end, instructions=instructions)

json_methods = {
    f"{m.start_addr}": m.instructions for m in methods.values()
}
with open(f'{InputFileName}.normalized_code.json', 'w') as f:
    json.dump(json_methods, f, indent=4)

idc.qexit(0)
