"""
SDN Manager

管理 SDN 生成的去噪后候选代码片段中间产物。
"""

import json
import sys
from pathlib import Path
from typing import List, Dict

# Add parent directory to path for importing sdn
CURRENT_DIR = Path(__file__).parent.resolve()
GENERATE_DIR = CURRENT_DIR.parent
if str(GENERATE_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATE_DIR))


class SDNManager:
    """
    管理 SDN 中间产物：去噪后的候选代码片段
    
    职责：
    1. 检查去噪结果是否已存在
    2. 加载去噪后的结果
    3. 调用 SDN 对 CCR 结果进行去噪（如果不存在）
    
    去噪分类：
    - strong: 高置信度候选（可直接信任）
    - backup: 中等置信度（仅用于命名/结构参考）
    - uncertain: 低置信度（不确定性片段）
    """
    
    def __init__(self, sdn_dir: Path):
        """
        Args:
            sdn_dir: SDN 工作目录，例如 data/generated/x64_O2/shared/sdn
        """
        self.sdn_dir = Path(sdn_dir)
        self.filtered_file = self.sdn_dir / "sdn_filtered.json"
    
    def exists(self) -> bool:
        """检查去噪结果是否已存在"""
        return self.filtered_file.exists()
    
    def load(self) -> List[Dict]:
        """
        加载去噪后的结果
        
        Returns:
            List of dicts, each containing:
                - filter_strong: List[str], 高置信度候选
                - filter_backup: List[str], 中等置信度候选
                - filter_uncertain: List[str], 低置信度候选
        """
        if not self.exists():
            raise FileNotFoundError(f"SDN filtered results not found at {self.filtered_file}")
        
        with open(self.filtered_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def create(self, ccr_candidates: List[Dict]) -> List[Dict]:
        """
        运行 SDN 去噪
        
        Args:
            ccr_candidates: CCR 输出的候选代码片段列表
                每个元素应包含 'probed_sources' 字段
        
        Returns:
            去噪后的结果列表，包含分类后的候选
        """
        self.sdn_dir.mkdir(parents=True, exist_ok=True)
        
        # Import SDN module
        from capd.sdn.run_sdn import run_filtering
        from config import get_module_config
        
        print(f"[SDNManager] Running SDN filtering...")
        config = get_module_config("sdn")
        filtered = run_filtering(ccr_candidates, config)
        
        # Save results
        with open(self.filtered_file, 'w', encoding='utf-8') as f:
            json.dump(filtered, f, indent=2, ensure_ascii=False)
        print(f"[SDNManager] Saved filtered results to {self.filtered_file}")
        
        # Print statistics
        self._print_stats(filtered)
        
        return filtered
    
    def get_or_create(self, ccr_candidates: List[Dict]) -> List[Dict]:
        """
        存在则加载，不存在则创建
        
        Args:
            ccr_candidates: CCR 候选，用于生成（如果不存在）
        
        Returns:
            去噪后的结果列表
        """
        if self.exists():
            print(f"[SDNManager] Loading existing filtered results from {self.filtered_file}")
            return self.load()
        return self.create(ccr_candidates)
    
    def _print_stats(self, filtered: List[Dict]):
        """打印去噪统计信息"""
        total = len(filtered)
        if total == 0:
            return
        
        strong_count = sum(len(item.get('filter_strong', [])) for item in filtered)
        backup_count = sum(len(item.get('filter_backup', [])) for item in filtered)
        uncertain_count = sum(len(item.get('filter_uncertain', [])) for item in filtered)
        
        print(f"[SDNManager] Filtering statistics:")
        print(f"  - Total samples: {total}")
        print(f"  - Strong candidates: {strong_count} (avg {strong_count/total:.1f}/sample)")
        print(f"  - Backup candidates: {backup_count} (avg {backup_count/total:.1f}/sample)")
        print(f"  - Uncertain candidates: {uncertain_count} (avg {uncertain_count/total:.1f}/sample)")
