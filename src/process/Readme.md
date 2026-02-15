# Binary Analysis Pipeline

A unified pipeline to process binary and source code, match functions, and generate datasets for various downstream tasks (BinT5, HexT5, CP-BCS, ProRec).

## Directory Structure

```text
process/
├── pipeline.py          # Main driver script
├── scripts/
│   ├── ida_extract.py   # IDAPython script for extracting CFG, CG, ASM, Decompilation
│   └── src_extract.py   # Script for scanning and extracting source code functions
├── lib/                 # Shared libraries for analysis (CFG analysis, ProRec data dependency)
└── result/           # (Auto-generated) Output directory for datasets
```

## Usage

Run the pipeline using `python3 process/pipeline.py`. You need to specify the binary directory, source directory, architecture/optimization level, and IDA Pro path.

```bash
python3 process/pipeline.py \
  --bin-dir /path/to/binary/x64_O3 \
  --src-dir /path/to/source_code \
  --arch-opt x64_O3 \
  --output-dir process/result \
  --ida-path /path/to/idat
```

### Arguments

- `--bin-dir`: Directory containing the binary files. 
  - Expects subdirectories for each project (e.g., `openssl/`).
  - Inside each project directory, expects stripped binaries (`*.elf`) and a `unstrip/` folder containing corresponding unstripped binaries.
- `--src-dir`: Directory containing the source code.
- `--arch-opt`: A string identifier for the architecture and optimization level (e.g., `x64_O3`, `arm_O2`). This is used to name the output subdirectory.
- `--output-dir`: Base directory where results will be saved (default: `process/result`).
- `--ida-path`: Path to the IDA Pro text-mode executable (`idat` or `idat64`).

## Outputs

The pipeline generates the following files in `process/result/<arch_opt>/`:

1.  **`baseline.pkl.gz`**: A comprehensive dataset containing all fields required for **BinT5, HexT5, CP-BCS, Misum and ProRec**.
2.  **`dataset.pkl.gz`**: A dataset containing only Control Flow Graph (CFG) data and Call Graph (CG) data.

Additionally, intermediate JSON files extracted from IDA are cached in `intermediate/` to speed up subsequent runs.

## Dependencies

- Python 3.8.10
- IDA Pro 9.1 (with Hex-Rays Decompiler)
- Python packages: `networkx`, `tqdm`
