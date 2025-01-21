"""
漏洞数据采集器包

提供了多个数据源的漏洞数据采集实现：
- NVD: 国家漏洞数据库
- Debian: Debian安全公告
- GitHub: GitHub安全公告
- RedHat: RedHat安全公告
"""

from .base import BaseVulnerabilityCollector
from .nvd import NVDCollector
from .debian import DebianCollector
from .github import GitHubCollector
from .redhat import RedHatCollector
from .factory import VulnerabilityCollectorFactory

__all__ = [
    'BaseVulnerabilityCollector',
    'NVDCollector',
    'DebianCollector',
    'GitHubCollector',
    'RedHatCollector',
    'VulnerabilityCollectorFactory'
] 