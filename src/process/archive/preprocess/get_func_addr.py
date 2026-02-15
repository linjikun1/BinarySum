import idc
import idautils
import idaapi
import ida_auto
import pickle

inputFileName = idc.get_input_file_path()

# 等待 IDA 自动分析完成
idaapi.auto_wait()

# 获取段起止地址的映射
segment_ranges = {}
for seg_ea in idautils.Segments():
    seg_name = idc.get_segm_name(seg_ea)
    segment_ranges[seg_name] = (seg_ea, idc.get_segm_end(seg_ea))

print("All Segment Names:", list(segment_ranges.keys()))

# 关心的段
target_segments = ['.text', '.init.text', '.exit.text']
methods = {}

# # 先对 .init.text 和 .exit.text 段强制进行分析
# for seg in ['.init.text', '.exit.text']:
#     if seg in segment_ranges:
#         start, end = segment_ranges[seg]
#         print(f"Analyzing segment: {seg} from {hex(start)} to {hex(end)}")
#         ida_auto.analyze_range(start, end)

# 遍历所有函数，不使用段范围
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
pickle.dump(methods, open('{}.func_names_and_address'.format(inputFileName), 'wb'), protocol=2)
idc.qexit(0)
