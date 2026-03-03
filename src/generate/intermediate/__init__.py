"""
Intermediate Products Management Module

管理生成流程中的中间产物：
- CFGManager: HPSS 生成的 CFG 摘要
- CCRLoader: CCR 训练好的候选代码片段（只读）
- SDNManager: SDN 去噪后的候选代码片段

Usage:
    from intermediate import CFGManager, CCRLoader, SDNManager
    
    # M2: 获取或创建 CFG 摘要
    cfg_mgr = CFGManager(hpss_dir)
    cfg_summary = cfg_mgr.get_or_create(test_data)
    
    # M3: 加载 CCR 候选
    ccr_loader = CCRLoader(ccr_dir)
    candidates = ccr_loader.load()  # 不存在会报错提示训练
    
    # M4: 获取或创建去噪结果
    sdn_mgr = SDNManager(sdn_dir)
    filtered = sdn_mgr.get_or_create(candidates)
"""

from .hpss_manager import HPSSManager
from .ccr_loader import CCRLoader
from .sdn_manager import SDNManager

__all__ = ['HPSSManager', 'CCRLoader', 'SDNManager']
