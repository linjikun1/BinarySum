# CCR (Cross-modal Code Retrieval)

集成自 [ProRec](https://arxiv.org/abs/2405.19581) (NeurIPS'24)

---

## BinarySum 集成

本模块作为 **CCR (Cross-modal Code Retrieval)** 组件集成到 BinarySum 中。

CCR 是**独立训练模块**，BinarySum 主流程通过 `intermediate.CCRLoader` 加载其产物，不会自动触发训练。

### 前置准备

**1. 数据** (由 BinarySum 生成):
```
BinarySum/data/processed/<arch>/dataset.pkl.gz
```

**2. 模型** (需手动下载到 `ccr/model/` 目录):

| 模型 | 目录名 | 说明 |
|------|--------|------|
| LongCodeArt-x86 | `model/longcodeart-x86` | x86 架构汇编编码器 |
| LongCodeArt-arm | `model/longcodeart-arm` | ARM 架构汇编编码器 |
| CodeLlama-13b | `model/CodeLlama-13b-hf` | 源代码模型 (无架构区分) |
| CodeT5p-embedding | `model/codet5p-110m-embedding` | 源代码嵌入模型 (无架构区分) |

**下载地址:**
- LongCodeArt: https://huggingface.co/PurCL/longcodeart-ep0.3-block200-26m
- CodeLlama-13b: https://huggingface.co/codellama/CodeLlama-13b-hf
- CodeT5p-embedding: https://huggingface.co/Salesforce/codet5p-110m-embedding

### 一键运行

```bash
cd BinarySum/src/generate/capd/ccr
bash run.sh x64_O3   # 或 arm_O3 等
```

**输出:** `../../../../data/generated/x64_O3/shared/ccr/ccr_candidates.json`

### 运行 BinarySum M3/M4

CCR 训练完成后，BinarySum 主流程会自动加载产物：

```bash
cd ../../../..  # 返回 BinarySum 根目录

# M3: HPSS + CCR
python main.py generate --arch x64_O3 --mode M3

# M4: HPSS + CCR + SDN
python main.py generate --arch x64_O3 --mode M4
```

**注意:** 如果 `ccr_candidates.json` 不存在，主流程会报错并提示运行训练。

### 架构关系

```
BinarySum Generate Pipeline:
├── intermediate/
│   └── ccr_loader.py          # 加载本模块产物 (只读)
├── hpss/                       # M2/M3/M4: CFG摘要生成
├── capd/
│   ├── ccr/                    # 本目录: 独立训练
│   │   ├── run.sh             # 训练入口
│   │   └── src/               # 训练代码
│   └── sdn/                    # M4: 去噪网络
└── synthesizer/                # 最终摘要合成

数据流:
  M3: test_data → [HPSS] → cfg_summary ─┐
                                         ├→ Synthesizer
        [CCR训练] → ccr_candidates ─────┘
  
  M4: test_data → [HPSS] → cfg_summary ─────────────────┐
                                                         ├→ Synthesizer
        [CCR训练] → ccr_candidates → [SDN] → filtered ──┘
```

### 时间估算

| Step | Time (4x A100-80G) |
|------|-------------------|
| CASP Training | ~2h |
| Prober Training | ~3h |
| Probing (Signature) | ~2h |
| Probing (Continue) | ~2h |
| **Total** | **~10h** |
