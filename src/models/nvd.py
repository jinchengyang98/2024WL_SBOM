#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
NVD数据模型模块

定义了NVD（国家漏洞数据库）特有的数据结构和转换方法。
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from .entities import (
    Vulnerability, Package, Version, Reference, CVSSMetrics
)

@dataclass
class CPEMatch:
    """CPE匹配信息"""
    cpe23Uri: str
    vulnerable: bool
    versionStartIncluding: Optional[str] = None
    versionStartExcluding: Optional[str] = None
    versionEndIncluding: Optional[str] = None
    versionEndExcluding: Optional[str] = None

@dataclass
class Node:
    """配置节点"""
    operator: str  # AND, OR
    negate: bool = False
    cpe_match: List[CPEMatch] = field(default_factory=list)
    children: List['Node'] = field(default_factory=list)

@dataclass
class NVDConfiguration:
    """NVD配置信息"""
    nodes: List[Node] = field(default_factory=list)

@dataclass
class NVDData:
    """NVD漏洞数据"""
    id: str
    published: datetime
    lastModified: datetime
    vulnStatus: str
    descriptions: List[Dict[str, str]]
    metrics: Dict[str, Any]
    references: List[Dict[str, Any]]
    configurations: List[Dict[str, Any]]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NVDData':
        """从NVD API响应数据创建实例"""
        cve = data.get('cve', {})
        return cls(
            id=cve.get('id'),
            published=datetime.fromisoformat(cve.get('published')),
            lastModified=datetime.fromisoformat(cve.get('lastModified')),
            vulnStatus=cve.get('vulnStatus'),
            descriptions=cve.get('descriptions', []),
            metrics=cve.get('metrics', {}),
            references=cve.get('references', []),
            configurations=cve.get('configurations', [])
        )
    
    def to_vulnerability(self) -> Vulnerability:
        """转换为通用漏洞模型"""
        # 提取描述（优先使用英文）
        description = next(
            (desc['value'] for desc in self.descriptions if desc.get('lang') == 'en'),
            next((desc['value'] for desc in self.descriptions), None)
        )
        
        # 提取CVSS评分
        cvss_v3 = self._extract_cvss_v3()
        cvss_v2 = self._extract_cvss_v2()
        
        # 提取受影响的包
        affected_packages = self._extract_affected_packages()
        
        # 提取参考链接
        references = [
            Reference(
                url=ref.get('url'),
                source=ref.get('source'),
                tags=ref.get('tags', [])
            )
            for ref in self.references
        ]
        
        return Vulnerability(
            id=self.id,
            source='NVD',
            description=description,
            published_date=self.published,
            last_modified_date=self.lastModified,
            status=self.vulnStatus,
            cvss_v3=cvss_v3,
            cvss_v2=cvss_v2,
            affected_packages=affected_packages,
            references=references,
            raw_data={'cve': data}
        )
    
    def _extract_cvss_v3(self) -> Optional[CVSSMetrics]:
        """提取CVSS v3评分信息"""
        cvss_v3 = self.metrics.get('cvssMetricV31', [])
        if not cvss_v3:
            cvss_v3 = self.metrics.get('cvssMetricV30', [])
            
        if cvss_v3:
            cvss_data = cvss_v3[0].get('cvssData', {})
            return CVSSMetrics(
                version=cvss_data.get('version'),
                vector_string=cvss_data.get('vectorString'),
                base_score=cvss_data.get('baseScore'),
                base_severity=cvss_data.get('baseSeverity'),
                exploitability_score=cvss_v3[0].get('exploitabilityScore'),
                impact_score=cvss_v3[0].get('impactScore')
            )
        return None
    
    def _extract_cvss_v2(self) -> Optional[CVSSMetrics]:
        """提取CVSS v2评分信息"""
        cvss_v2 = self.metrics.get('cvssMetricV2', [])
        
        if cvss_v2:
            cvss_data = cvss_v2[0].get('cvssData', {})
            return CVSSMetrics(
                version='2.0',
                vector_string=cvss_data.get('vectorString'),
                base_score=cvss_data.get('baseScore'),
                base_severity=cvss_v2[0].get('baseSeverity'),
                exploitability_score=cvss_v2[0].get('exploitabilityScore'),
                impact_score=cvss_v2[0].get('impactScore')
            )
        return None
    
    def _extract_affected_packages(self) -> List[Package]:
        """从CPE配置中提取受影响的包信息"""
        packages = []
        
        def process_node(node: Dict[str, Any]) -> None:
            """处理配置节点"""
            for cpe_match in node.get('cpeMatch', []):
                cpe = cpe_match.get('cpe23Uri', '')
                if not cpe:
                    continue
                    
                # 解析CPE URI
                # 格式：cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                parts = cpe.split(':')
                if len(parts) < 5:
                    continue
                    
                vendor = parts[3]
                product = parts[4]
                version = parts[5] if len(parts) > 5 else '*'
                
                # 创建版本范围
                version_range = {
                    'start_including': cpe_match.get('versionStartIncluding'),
                    'start_excluding': cpe_match.get('versionStartExcluding'),
                    'end_including': cpe_match.get('versionEndIncluding'),
                    'end_excluding': cpe_match.get('versionEndExcluding')
                }
                
                # 创建或更新包信息
                pkg_name = f"{vendor}/{product}"
                pkg = next((p for p in packages if p.name == pkg_name), None)
                if not pkg:
                    pkg = Package(
                        name=pkg_name,
                        ecosystem='cpe',
                        platform=parts[2]  # a=application, o=os, h=hardware
                    )
                    packages.append(pkg)
                
                # 添加版本信息
                if version != '*':
                    pkg.versions.append(Version(
                        version=version,
                        status='affected' if cpe_match.get('vulnerable', True) else 'fixed'
                    ))
            
            # 递归处理子节点
            for child in node.get('children', []):
                process_node(child)
        
        # 处理所有配置节点
        for config in self.configurations:
            for node in config.get('nodes', []):
                process_node(node)
        
        return packages 