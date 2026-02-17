import gzip
import pickle
from tqdm import tqdm

with gzip.open('x64_O3/cfg_data.pkl.gz', 'rb') as f:
    data1 = pickle.load(f)

with gzip.open('x64_O3/cg_data_codeart.pkl.gz', 'rb') as f:
    data2 = pickle.load(f)

result = []
for item1, item2 in tqdm(zip(data1, data2)):
    item = item1 | item2
    result.append(item)

with gzip.open('x64_O3/dataset.pkl.gz', 'wb', compresslevel=5) as f:
    pickle.dump(result, f)
