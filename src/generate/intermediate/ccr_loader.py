"""
CCR Loader

加载 CCR 训练好的候选代码片段。
注意：CCR 训练是独立的，本模块只负责加载产物，不管理训练过程。
"""

import json
import re
from pathlib import Path
from typing import List, Dict


class CCRLoader:
    """
    加载 CCR 产物：probed_sources（只读，训练由外部管理）
    
    职责：
    1. 检查 CCR 产物是否存在
    2. 加载候选代码片段
    3. 标准化输出格式
    
    注意：
    - CCR 训练需要 ~10小时，由用户在单独环境中手动执行
    - 本模块只负责读取 ccr_candidates.json
    """
    
    def __init__(self, ccr_dir: Path):
        """
        Args:
            ccr_dir: CCR 输出目录，例如 data/generated/x64_O2/shared/ccr
        """
        self.ccr_dir = Path(ccr_dir)
        self.candidates_file = self.ccr_dir / "ccr_candidates.json"
    
    def exists(self) -> bool:
        """检查 CCR 产物是否存在"""
        return self.candidates_file.exists()
    
    def load(self) -> List[Dict]:
        """
        加载候选代码片段
        
        Returns:
            List of dicts, each containing:
                - probed_sources: List[str], 候选源代码片段
                - signatures: List[str], 对应的签名
                - confidence_scores: List[float], 置信度分数
        
        Raises:
            FileNotFoundError: 如果 CCR 产物不存在，提示用户手动运行训练
        """
        if not self.exists():
            raise FileNotFoundError(
                f"\n{'='*60}\n"
                f"CCR results not found at:\n"
                f"  {self.candidates_file}\n\n"
                f"CCR (Cross-modal Code Retrieval) requires manual training.\n"
                f"Please run the following commands:\n\n"
                f"  cd BinarySum/src/generate/capd/ccr\n"
                f"  bash run.sh <arch>  # e.g., x64_O3, arm_O2\n\n"
                f"Training time: ~10 hours (4x A100-80G)\n"
                f"{'='*60}"
            )
        
        with open(self.candidates_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 标准化字段格式
        return [self._normalize(item) for item in data]
    
    def _normalize(self, item: Dict) -> Dict:
        """
        标准化 CCR 输出格式
        
        确保输出包含以下字段：
        - probed_sources: 候选源代码片段列表
        - signatures: 签名列表（可选）
        - confidence_scores: 置信度分数列表（可选）
        """
        normalized = {
            'probed_sources': item.get('probed_sources', []),
            'signatures': item.get('signatures', []),
            'confidence_scores': item.get('confidence_scores', [])
        }
        
        # 清理 probed_sources 中的特殊标记（<asm_token>、</s>、<s> 等序列模型token）
        cleaned_sources = []
        for source in normalized['probed_sources']:
            if '<asm_token>' in source:
                source = source.split('<asm_token>\n')[-1]
            # 清理所有残留的特殊token（</s>、<s>、<unk> 等）
            source = re.sub(r'</?[a-z_]+>', '', source)
            source = source.strip()
            if source:  # 过滤掉清理后变为空的条目
                cleaned_sources.append(source)
        normalized['probed_sources'] = cleaned_sources
        
        return normalized
    
    def validate(self) -> bool:
        """
        验证产物完整性
        
        检查：
        1. 文件存在
        2. 每个样本都有 probed_sources 字段
        3. probed_sources 非空
        
        Returns:
            True if valid, False otherwise
        """
        try:
            data = self.load()
            for i, item in enumerate(data):
                if 'probed_sources' not in item:
                    print(f"[CCRLoader] Warning: Item {i} missing 'probed_sources'")
                    return False
                if not item['probed_sources']:
                    print(f"[CCRLoader] Warning: Item {i} has empty 'probed_sources'")
            return True
        except Exception as e:
            print(f"[CCRLoader] Validation failed: {e}")
            return False
    
    def get_candidates_count(self) -> int:
        """
        获取每个样本的候选片段数量
        
        Returns:
            平均候选数量
        """
        data = self.load()
        if not data:
            return 0
        total = sum(len(item.get('probed_sources', [])) for item in data)
        return total // len(data)
