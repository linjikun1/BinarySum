#!/bin/bash
# ============================================================
# CCR 一键训练脚本
# 
# 用法:
#   cd BinarySum/src/generate/capd/ccr
#   bash run.sh x64_O3
#
# 输入: data/processed/<arch>/dataset.pkl.gz
# 输出: data/generated/<arch>/shared/ccr/ccr_candidates.json
# ============================================================

set -e

# ================= 参数配置 =================
ARCH="${1:-x64_O3}"
PLACEHOLDER="x64_O1"  # yaml 文件中的架构占位符

# 路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARYSUM_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

INPUT_DATA="$BINARYSUM_ROOT/data/processed/$ARCH/dataset.pkl.gz"
OUTPUT_DIR="$BINARYSUM_ROOT/data/generated/$ARCH/shared/ccr"

# 显卡配置
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0,1,2,3}"
export NPROC_PER_NODE="${NPROC_PER_NODE:-4}"
export PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:128,expandable_segments:True

PYTHON_EXEC="${PYTHON_EXEC:-$(which python3)}"
TORCHRUN_EXEC="${TORCHRUN_EXEC:-$(which torchrun)}"
ACCELERATE_EXEC="${ACCELERATE_EXEC:-$(which accelerate)}"

# ================= 检查输入 =================
echo "============================================================"
echo "CCR Training"
echo "============================================================"
echo "Architecture: $ARCH"
echo "Input:        $INPUT_DATA"
echo "Output:       $OUTPUT_DIR/ccr_candidates.json"
echo "GPUs:         $CUDA_VISIBLE_DEVICES"
echo "============================================================"

if [ ! -f "$INPUT_DATA" ]; then
    echo "ERROR: Input not found: $INPUT_DATA"
    echo "Run: python main.py process --arch $ARCH"
    exit 1
fi

# 创建目录
mkdir -p "$SCRIPT_DIR/save/$ARCH"
mkdir -p "$OUTPUT_DIR"

cd "$SCRIPT_DIR/src"
CONFIG_DIR="scripts/configs"

# ================= 替换架构占位符 =================
echo "[Config] Replacing $PLACEHOLDER -> $ARCH..."

# 根据架构选择 longcodeart
case "$ARCH" in
    arm_*) LONGCODEART="longcodeart-arm" ;;
    *)     LONGCODEART="longcodeart-x86" ;;
esac

# 替换所有 yaml 文件中的占位符
for yaml in "$CONFIG_DIR"/*.yaml; do
    sed -i "s|$PLACEHOLDER|$ARCH|g" "$yaml"
    # 替换 longcodeart 架构版本
    sed -i "s|longcodeart-x86|$LONGCODEART|g" "$yaml"
    sed -i "s|longcodeart-arm|$LONGCODEART|g" "$yaml"
done

echo "[Config] Done."

# ================= Step 0: 准备数据 =================
echo ""
echo "[Step 0] Preparing CASP data..."
$PYTHON_EXEC ../data/run_casp_data_cg.py --input "$INPUT_DATA" --arch "$ARCH"

# ================= Step 1: CASP 训练 =================
echo ""
echo "[Step 1] CASP Training (~2h)..."
$TORCHRUN_EXEC --nproc_per_node=$NPROC_PER_NODE run_casp.py "$CONFIG_DIR/train_casp_moco.yaml"

# ================= Step 2: Prober 训练 =================
echo ""
echo "[Step 2] Prober Training (~3h)..."
$TORCHRUN_EXEC --nproc_per_node=$NPROC_PER_NODE run_prober.py "$CONFIG_DIR/train_prober.yaml"

# ================= Step 3: Probing 数据 =================
echo ""
echo "[Step 3] Preparing Probing data..."
$PYTHON_EXEC ../data/probed_data_cg.py --input "$INPUT_DATA" --arch "$ARCH"

# ================= Step 4: Probing Signature =================
echo ""
echo "[Step 4] Probing Signatures (~2h)..."
$ACCELERATE_EXEC launch --num_processes=$NPROC_PER_NODE \
    big_model_quantized_probing.py "$CONFIG_DIR/probe.yaml"

# ================= Step 5: Filter =================
echo ""
echo "[Step 5] Filtering signatures..."
$PYTHON_EXEC score_and_filter_signature.py "$CONFIG_DIR/filter_sig.yaml"

# ================= Step 6: Continue Probing 数据 =================
echo ""
echo "[Step 6] Preparing Continue data..."
$PYTHON_EXEC ../data/probed_continue_data_cg.py \
    --input "$INPUT_DATA" \
    --arch "$ARCH" \
    --scored-signatures "$SCRIPT_DIR/save/$ARCH/scored_signatures.json"

# ================= Step 7: Probing Continue =================
echo ""
echo "[Step 7] Probing Bodies (~2h)..."
$ACCELERATE_EXEC launch --num_processes=$NPROC_PER_NODE \
    big_model_quantized_probing_continue.py "$CONFIG_DIR/probe_continue.yaml"

# ================= 复制结果 =================
cp "$SCRIPT_DIR/save/$ARCH/output/ccr_candidates.json" "$OUTPUT_DIR/"

echo ""
echo "============================================================"
echo "CCR Training Complete!"
echo "============================================================"
echo "Output: $OUTPUT_DIR/ccr_candidates.json"
echo ""
echo "Run BinarySum:"
echo "  cd $BINARYSUM_ROOT"
echo "  python main.py generate --arch $ARCH --mode M3"
echo "============================================================"
