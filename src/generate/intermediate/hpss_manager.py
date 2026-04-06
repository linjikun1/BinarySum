"""
CFG Summary Manager

管理 HPSS 生成的 CFG 摘要中间产物。
"""

import json
import sys
from pathlib import Path
from typing import List, Dict

# Add parent directory to path for importing hpss
CURRENT_DIR = Path(__file__).parent.resolve()
GENERATE_DIR = CURRENT_DIR.parent
if str(GENERATE_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATE_DIR))


class HPSSManager:
    """
    管理 HPSS 中间产物: cfg_summary
    
    职责:
    1. 检查 cfg_summary 是否存在
    2. 加载已生成的 cfg_summary
    3. 调用 HPSS 生成新的 cfg_summary(如果不存在)
    """
    
    def __init__(self, hpss_dir: Path):
        """
        Args:
            hpss_dir: HPSS 工作目录，例如 data/generated/x64_O2/shared/hpss
        """
        self.hpss_dir = Path(hpss_dir)
        self.cfg_file = self.hpss_dir / "cfg_summary.json"
        self.paths_file = self.hpss_dir / "cfg_paths.json"
    
    def exists(self) -> bool:
        """检查 cfg_summary 是否已存在"""
        return self.cfg_file.exists()
    
    def load(self) -> List[Dict]:
        """
        加载已生成的 cfg_summary
        
        Returns:
            List of dicts, each containing 'cfg_summary' field
        """
        if not self.exists():
            raise FileNotFoundError(f"CFG summary not found at {self.cfg_file}")
        
        with open(self.cfg_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _save_temp_input(self, test_data: List[Dict]) -> Path:
        """保存临时输入文件供 HPSS 使用（JSON格式）"""
        temp_file = self.hpss_dir / "temp_input.json"
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(test_data, f, ensure_ascii=False)
        return temp_file
    
    def create(self, test_data: List[Dict]) -> List[Dict]:
        """
        生成 cfg_summary
        
        流程：
        1. 提取 CFG 路径 → cfg_paths.json
        2. 生成摘要 → cfg_summary.json
        
        Args:
            test_data: 测试数据列表，每个元素应包含 'cfg' 字段
            
        Returns:
            生成的 cfg_summary 列表
        """
        self.hpss_dir.mkdir(parents=True, exist_ok=True)
        
        # Add hpss directory to path for its internal imports
        hpss_dir = GENERATE_DIR / "hpss"
        if str(hpss_dir) not in sys.path:
            sys.path.insert(0, str(hpss_dir))
        
        # Import HPSS modules
        from hpss.src.extract_paths import extract_cfg_paths
        from hpss.src.hpss_summary import generate_cfg_summaries
        from config import get_module_config
        
        # Save temp input for HPSS
        temp_input = self._save_temp_input(test_data)
        
        # Step 1: 提取 CFG 路径
        if not self.paths_file.exists():
            print(f"[HPSSManager] Extracting CFG paths...")
            extract_cfg_paths(str(temp_input), str(self.paths_file))
            print(f"[HPSSManager] Saved paths to {self.paths_file}")
        
        # Step 2: 生成 CFG 摘要（中间表示）
        print(f"[HPSSManager] Generating CFG summaries (intermediate representation)...")
        config = get_module_config("hpss")
        generate_cfg_summaries(str(temp_input), str(self.paths_file), str(self.cfg_file), config)
        
        # Clean up temp file
        if temp_input.exists():
            temp_input.unlink()
        
        print(f"[HPSSManager] Saved CFG summary to {self.cfg_file}")
        
        return self.load()
    
    def get_or_create(self, test_data: List[Dict]) -> List[Dict]:
        """
        存在则加载（校验数量+函数地址对齐），不存在则创建
        
        Args:
            test_data: 测试数据，用于生成（如果不存在或内容不匹配）
            
        Returns:
            cfg_summary 列表
        """
        if self.exists():
            existing = self.load()
            stale = False
            if len(existing) != len(test_data):
                print(f"[HPSSManager] WARNING: cfg_summary has {len(existing)} items but test_data has {len(test_data)} items. Regenerating...")
                stale = True
            else:
                # Content alignment check: compare function_addr anchors
                existing_addrs = [item.get('function_addr', '') for item in existing]
                test_addrs = [item.get('function_addr', '') for item in test_data]
                if any(ea for ea in existing_addrs):  # only check if anchors exist
                    mismatches = sum(1 for ea, ta in zip(existing_addrs, test_addrs) if ea != ta)
                    if mismatches > 0:
                        print(f"[HPSSManager] WARNING: cfg_summary has {mismatches}/{len(existing)} function_addr mismatches with test_data. Regenerating...")
                        stale = True
            
            if stale:
                self.cfg_file.unlink(missing_ok=True)
                # cfg_paths.json is deterministic (no LLM), keep it for reuse
            else:
                print(f"[HPSSManager] Loading existing CFG summary from {self.cfg_file}")
                return existing
        return self.create(test_data)
