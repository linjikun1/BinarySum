import json

with open("/home/linjk/Downloads/test_refined.json", 'r') as f:
    test_data = json.load(f)
with open("/home/linjk/Downloads/valid_refined.json", 'r') as f:
    valid_data = json.load(f)
with open("/home/linjk/Downloads/train_refined.json", 'r') as f:
    train_data = json.load(f)

data = test_data + valid_data + train_data
print(len(data))
for item in data:
    if "all resources associated with context_handle" in item['comment']:
        print(f"funcname: {item['function_name']}, strip_funcname: {item['function_name_in_strip']}, comment: {item['comment']}")