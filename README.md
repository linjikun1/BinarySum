# BinarySum: Binary Code Summary Generation Framework

This repository implements **HPSS-CAPD**, a framework for generating summaries for stripped binary code.

## Requirements

- Python 3.8+
- IDA Pro 9.1 (with Hex-Rays Decompiler, for processing)
- OpenAI API Key (for generation)

## Installation

```bash
pip install -r requirements.txt

# Optional: LLM-based evaluation
pip install -U deepeval==3.7.2
```

## Data Directory Structure

```
BinarySum/
├── data/
│   ├── raw/                        # 原始数据
│   │   ├── binary/               # 剥离二进制文件
│   │   │   ├── x64_O3/
│   │   │   │   └── <project>/
│   │   │   │       ├── xxx.elf
│   │   │   │       └── unstrip/xxx.elf
│   │   │   └── arm_O2/
│   │   └── source/                 # 源代码
│   │       └── <project>-src/
│   │
│   ├── processed/                  # 预处理后的数据
│   │   ├── source_info.json        # 全局源代码信息
│   │   └── <arch>/
│   │       ├── intermediate/       # IDA 中间结果 (可缓存)
│   │       ├── baseline.pkl.gz     # 全字段数据集
│   │       └── dataset.pkl.gz      # CFG+CG 数据集
│   │
│   ├── generated/                  # 摘要生成结果
│   │   └── <arch>/
│   │       ├── M1/summary.json
│   │       ├── M2/
│   │       │   ├── hpss_paths.json
│   │       │   ├── hpss_summary.json
│   │       │   └── summary.json
│   │       ├── M3/
│   │       │   ├── hpss_*.json
│   │       │   ├── ccr_candidates.json
│   │       │   └── summary.json
│   │       └── M4/
│   │           ├── hpss_*.json
│   │           ├── ccr_candidates.json
│   │           ├── sdn_filtered.json
│   │           └── summary.json
│   │
│   └── results/                    # 评估结果
│       └── <arch>/
│           ├── M1_metrics.json
│           ├── M2_metrics.json
│           ├── M3_metrics.json
│           └── M4_metrics.json
│
├── src/
│   ├── process/
│   │   ├── run_process.py          # 数据处理入口
│   │   ├── scripts/               # IDA/源码提取脚本
│   │   └── lib/                   # 分析库
│   │
│   ├── generate/
│   │   ├── run_generate.py        # 摘要生成入口
│   │   ├── hpss/                  # HPSS: 层级化路径敏感摘要
│   │   │   └── run_hpss.py
│   │   ├── capd/                  # CAPD: 上下文感知程序去噪
│   │   │   ├── ccr/               #   CCR: 跨模态候选检索
│   │   │   └── sdn/               #   SDN: 语义去噪网络
│   │   └── synthesizer/           # 最终合成器
│   │       └── run_synthesis.py
│   │
│   └── evaluate/
│       ├── run_evaluation.py      # 评估入口
│       ├── n_gram_metrics/        # N-gram指标 (BLEU, ROUGE, METEOR)
│       ├── semantic_metrics/      # 语义指标 (CodeBERTScore, SIDE)
│       └── llm_eval/              # LLM评估 (deepeval)
│           ├── run_llm_eval.py    #   封装的评估器
│           └── deepeval_internal/ #   vendored deepeval源码
│
└── main.py                         # 统一入口
```

## Usage

### 1. Data Processing

Process binary files and align them with source code.

```bash
# 简化命令（使用默认路径）
python main.py process --arch x64_O3

# 处理所有架构
python main.py process --arch all

# 自定义路径
python main.py process \
  --arch x64_O3 \
  --bin-dir /path/to/binaries \
  --src-dir /path/to/source \
  --output-dir /path/to/output \
  --ida-path /path/to/idat
```

**Outputs:**
- `data/processed/<arch>/baseline.pkl.gz`: 全字段数据集
- `data/processed/<arch>/dataset.pkl.gz`: CFG+CG 数据集

### 2. Summary Generation (Ablation Modes)

| Mode | Description | Components |
|------|-------------|------------|
| M1 | Baseline | Decompiled Code only |
| M2 | + HPSS | Decompiled + CFG Description |
| M3 | + HPSS + CCR | M2 + Raw Source Candidates |
| M4 | Full | M3 + SDN Filtering |

```bash
# 简化命令（使用默认路径）
python main.py generate --arch x64_O3 --mode M1
python main.py generate --arch x64_O3 --mode M2
python main.py generate --arch x64_O3 --mode M3
python main.py generate --arch x64_O3 --mode M4

# 自定义输入输出
python main.py generate \
  --arch x64_O3 \
  --mode M4 \
  --input /path/to/dataset.pkl.gz \
  --output /path/to/summary.json
```

**Outputs:**
- `data/generated/<arch>/<mode>/summary.json`: 最终摘要

### 3. Evaluation

```bash
# 简化命令
python main.py evaluate --arch x64_O3 --mode M4 --ngram --semantic

# 自定义路径
python main.py evaluate \
  --arch x64_O3 \
  --mode M4 \
  --input-file /path/to/summary.json \
  --output-file /path/to/metrics.json \
  --ngram --semantic --llmeval
```

**Outputs:**
- `data/results/<arch>/<mode>_metrics.json`: 评估指标

## Quick Start

```bash
# 1. 准备数据
# 将二进制放到 data/raw/binaries/<arch>/<project>/
# 将源代码放到 data/raw/source/<project>-src/

# 2. 预处理
python main.py process --arch x64_O3

# 3. 生成摘要 (选择模式)
python main.py generate --arch x64_O3 --mode M4

# 4. 评估
python main.py evaluate --arch x64_O3 --mode M4 --ngram --semantic
```