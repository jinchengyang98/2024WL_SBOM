"""
漏洞数据模型包

提供了各种漏洞数据的模型定义：
- 基础实体模型
- NVD数据模型
- 数据库模型
"""

from .entities import *
from .nvd import NVDData

__all__ = [
    'NVDData'
] 