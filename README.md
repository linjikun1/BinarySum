# BinarySum: Binary Code Summary Generation Framework

This repository implements **HPSS-CAPD**, a framework for generating summary for stripped binary code.

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

## Directory Structure

```
BinarySum/
├── data/
│   ├── raw/                            # 原始数据
│   │   ├── binary/                     # 剥离二进制文件
│   │   │   ├── x64_O2/
│   │   │   │   └── <project>/
│   │   │   │       ├── xxx.elf
│   │   │   │       └── unstrip/xxx.elf
│   │   │   └── arm_O2/
│   │   └── source/                     # 源代码
│   │       └── <project>-src/
│   │
│   ├── processed/                      # 预处理后的数据
│   │   ├── source_info.json            # 全局源代码信息
│   │   └── <arch>/
│   │       ├── intermediate/           # IDA 中间结果 (可缓存)
│   │       ├── baseline.pkl.gz         # 全字段数据集
│   │       └── dataset.pkl.gz          # CFG+CG 数据集 (含 reference 字段)
│   │
│   ├── need_to_gen_augref.pkl.gz       # augref 中间产物：去重后待生成集合
│   └── final_ref.pkl.gz               # augref 中间产物：LLM 生成的参考摘要
│   │
│   ├── generated/                      # 摘要生成结果
│   │   └── <arch>/
│   │       ├── shared/                 # 共享数据 (复用优化)
│   │       │   ├── train.pkl.gz        # 训练集 (CCR)
│   │       │   ├── valid.pkl.gz        # 验证集 (CCR)
│   │       │   ├── test_filtered.json  # 测试集 (200条)
│   │       │   ├── hpss/               # HPSS 结果 (M2/M3/M4)
│   │       │   │   ├── hpss_paths.json
│   │       │   │   └── hpss_summary.json
│   │       │   ├── ccr/                # CCR 结果 (M3/M4)
│   │       │   │   └── ccr_candidates.json
│   │       │   └── sdn/                # SDN 结果 (M4)
│   │       │       └── sdn_filtered.json
│   │       ├── M1/summary.json
│   │       ├── M2/summary.json
│   │       ├── M3/summary.json
│   │       └── M4/summary.json
│   │
│   └── results/                        # 评估结果
│       └── <arch>/
│           ├── M1_metrics.json
│           ├── M2_metrics.json
│           ├── M3_metrics.json
│           └── M4_metrics.json
│
├── src/
│   ├── process/
│   │   ├── run_process.py              # 数据处理入口
│   │   ├── gen_augref.py               # LLM 参考摘要生成入口
│   │   ├── scripts/                    # IDA/源码提取脚本
│   │   └── lib/                        # 分析库
│   │
│   ├── generate/
│   │   ├── run_generate.py             # 摘要生成入口
│   │   ├── intermediate/               # 中间产物管理层
│   │   │   ├── cfg_manager.py          #   HPSS CFG摘要管理
│   │   │   ├── ccr_loader.py           #   CCR产物加载器
│   │   │   └── sdn_manager.py          #   SDN去噪管理
│   │   ├── hpss/                       # HPSS: 层级化路径敏感摘要 (M2/M3/M4)
│   │   │   └── run_hpss.py
│   │   ├── capd/                       # CAPD: 上下文感知程序去噪 (M3/M4)
│   │   │   ├── ccr/                    #   CCR: 跨模态候选检索 (需手动训练)
│   │   │   └── sdn/                    #   SDN: 语义去噪网络 (M4)
│   │   └── synthesizer/                # 最终合成器
│   │       └── run_synthesis.py
│   │
│   └── evaluate/
│       ├── run_evaluation.py           # 评估入口
│       ├── texsim/                     # 文本相似度指标 (BLEU, ROUGE, METEOR)
│       ├── semsim/                     # 语义相似度指标 (CodeBERTScore, SIDE)
│       └── llmjudge/                   # LLM评估 (deepeval)
│           ├── run_llm_eval.py         #   封装的评估器
│           └── deepeval_internal/      #   vendored deepeval源码
│
└── main.py                             # 统一入口
```

## Usage

**Quick Start:**
```bash
# 1. 准备数据: 将二进制放到 data/raw/binaries/<arch>/<project>/
# 2. 预处理: python main.py process --arch x64_O2
# 3. 生成参考摘要 (LLM): python main.py augref
# 4. 生成摘要: python main.py generate --arch x64_O2 --mode M4
# 5. 评估: python main.py evaluate --arch x64_O2 --mode M4 --texsim --semsim
```

### 1. Data Processing

Process binary files and align them with source code.

```bash
# 简化命令（使用默认路径）
python main.py process --arch x64_O2

# 处理所有架构
python main.py process --arch all

# 自定义路径
python main.py process \
  --arch x64_O2 \
  --bin-dir /path/to/binaries \
  --src-dir /path/to/source \
  --output-dir /path/to/output \
  --ida-path /path/to/idat
```

**Outputs:**
- `data/processed/<arch>/baseline.pkl.gz`: baseline 数据集
- `data/processed/<arch>/dataset.pkl.gz`: CFG+CG 数据集

### 2. Augmented Reference Generation

Process 完成后，可选地为所有架构的函数 source code 用 LLM 生成高质量参考摘要，并写回 `reference` 字段。

```bash
# 全流程一次跑完（collect → generate → apply）
python main.py augref

# 单独执行某步（支持断点续跑）
python main.py augref --step collect
python main.py augref --step generate
python main.py augref --step apply

# 自定义路径或 profile
python main.py augref --processed-dir /path/to/processed --work-dir /path/to/work --profile gpt
```

**Steps:**
| Step | Description | Input | Output |
|------|-------------|-------|--------|
| collect | 聚合所有架构 dataset.pkl.gz，去重 | `processed/<arch>/dataset.pkl.gz` | `data/need_to_gen_augref.pkl.gz` |
| generate | LLM 生成参考摘要（断点续跑） | `need_to_gen_augref.pkl.gz` | `data/final_ref.pkl.gz` |
| apply | 将 reference 写回各架构数据集 | `final_ref.pkl.gz` | `processed/<arch>/dataset.pkl.gz` + `baseline.pkl.gz` |

| Mode | Description | Components |
|------|-------------|------------|
| M1 | Baseline | Decompiled Code only |
| M2 | + HPSS | Decompiled + CFG Description |
| M3 | + HPSS + CCR | M2 + Raw Source Candidates |
| M4 | Full | M3 + SDN Filtering |

**架构与数据流:**

```
分层架构:
  Intermediate Layer: cfg_manager, ccr_loader, sdn_manager
  Innovation Layer:   HPSS (M2), CAPD-CCR/SDN (M3/M4)
  Synthesis Layer:    Final summary generation

数据流:
  M1: test_filtered → Synthesizer → summary.json
  M2: test_filtered → [CFGManager] → cfg_summary → Synthesizer → summary.json
  M3: test_filtered → [CFGManager] → cfg_summary ─┐
                                                   ├→ Synthesizer → summary.json
        [CCRLoader] → ccr_candidates ─────────────┘
  M4: test_filtered → [CFGManager] → cfg_summary ───────────────────────┐
                                                                        ├→ Synthesizer → summary.json
        [CCRLoader] → ccr_candidates → [SDNManager] → filtered ─────────┘
```

**注意:** M3/M4 模式需要先手动完成 CCR 模块的训练 (~10h)，详情请参考[ccr/README.md](src/generate/capd/ccr/README.md)。

```bash
# 简化命令（使用默认路径）
python main.py generate --arch x64_O2 --mode M1
python main.py generate --arch x64_O2 --mode M2
python main.py generate --arch x64_O2 --mode M3
python main.py generate --arch x64_O2 --mode M4

# 自定义输入输出
python main.py generate \
  --arch x64_O2 \
  --mode M4 \
  --input /path/to/dataset.pkl.gz \
  --output /path/to/summary.json
```

**Outputs:**
- `data/generated/<arch>/shared/`: 共享中间结果
- `data/generated/<arch>/<mode>/summary.json`: 最终摘要

### 3. Result Evaluation

```bash
# 简化命令
python main.py evaluate --arch x64_O2 --mode M4 --texsim --semsim

# 自定义路径
python main.py evaluate \
  --arch x64_O2 \
  --mode M4 \
  --input-file /path/to/summary.json \
  --output-file /path/to/metrics.json \
  --texsim --semsim --llmjudge
```

**Outputs:**
- `data/results/<arch>/<mode>_metrics.json`: 评估指标