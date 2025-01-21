#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
基础实体模型模块

定义了系统中的基本实体类型：
- 漏洞（Vulnerability）
- 软件包（Package）
- 版本（Version）
- 参考链接（Reference）
- CVSS评分（CVSSMetrics）
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

@dataclass
class Reference:
    """参考链接"""
    url: str
    source: str = "unknown"
    type: str = "other"
    tags: List[str] = field(default_factory=list)

@dataclass
class CVSSMetrics:
    """CVSS评分信息"""
    version: str
    vector_string: str
    base_score: float
    base_severity: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    status: Optional[str] = None

@dataclass
class Version:
    """软件版本"""
    version: str
    release: Optional[str] = None
    architecture: Optional[str] = None
    status: str = "unknown"  # affected, fixed, unknown
    repositories: List[str] = field(default_factory=list)

@dataclass
class Package:
    """软件包"""
    name: str
    ecosystem: Optional[str] = None  # npm, pypi, debian, redhat等
    platform: Optional[str] = None
    versions: List[Version] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    
    def is_affected(self, version: str) -> bool:
        """检查指定版本是否受影响"""
        # TODO: 实现版本比较逻辑
        return version in self.affected_versions

@dataclass
class Vulnerability:
    """漏洞基础模型"""
    # 基本信息
    id: str  # CVE ID或其他标识符
    source: str  # 数据源（NVD, GitHub, RedHat, Debian）
    title: Optional[str] = None
    description: Optional[str] = None
    
    # 时间信息
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    discovered_date: Optional[datetime] = None
    
    # 严重程度
    severity: Optional[str] = None  # HIGH, MEDIUM, LOW等
    cvss_v3: Optional[CVSSMetrics] = None
    cvss_v2: Optional[CVSSMetrics] = None
    
    # 状态信息
    status: str = "unknown"  # confirmed, rejected, unknown等
    scope: Optional[str] = None
    
    # 影响信息
    affected_packages: List[Package] = field(default_factory=list)
    affected_configurations: List[Dict[str, Any]] = field(default_factory=list)
    
    # 参考信息
    references: List[Reference] = field(default_factory=list)
    patches: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    # 原始数据
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'id': self.id,
            'source': self.source,
            'title': self.title,
            'description': self.description,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'discovered_date': self.discovered_date.isoformat() if self.discovered_date else None,
            'severity': self.severity,
            'cvss_v3': vars(self.cvss_v3) if self.cvss_v3 else None,
            'cvss_v2': vars(self.cvss_v2) if self.cvss_v2 else None,
            'status': self.status,
            'scope': self.scope,
            'affected_packages': [vars(pkg) for pkg in self.affected_packages],
            'affected_configurations': self.affected_configurations,
            'references': [vars(ref) for ref in self.references],
            'patches': self.patches,
            'notes': self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """从字典创建实例"""
        # 处理日期字段
        for date_field in ['published_date', 'last_modified_date', 'discovered_date']:
            if data.get(date_field):
                data[date_field] = datetime.fromisoformat(data[date_field].rstrip('Z'))
        
        # 处理CVSS评分
        if data.get('cvss_v3'):
            data['cvss_v3'] = CVSSMetrics(**data['cvss_v3'])
        if data.get('cvss_v2'):
            data['cvss_v2'] = CVSSMetrics(**data['cvss_v2'])
        
        # 处理受影响的包
        if data.get('affected_packages'):
            packages = []
            for pkg_data in data['affected_packages']:
                versions = []
                for ver_data in pkg_data.pop('versions', []):
                    versions.append(Version(**ver_data))
                pkg_data['versions'] = versions
                packages.append(Package(**pkg_data))
            data['affected_packages'] = packages
        
        # 处理参考链接
        if data.get('references'):
            data['references'] = [Reference(**ref) for ref in data['references']]
        
        return cls(**data)
    
    def merge(self, other: 'Vulnerability') -> None:
        """合并另一个漏洞实例的信息"""
        # 只合并来自同一个漏洞的信息
        if self.id != other.id:
            raise ValueError("Cannot merge vulnerabilities with different IDs")
        
        # 更新基本信息
        if other.title and not self.title:
            self.title = other.title
        if other.description and not self.description:
            self.description = other.description
        
        # 更新时间信息（使用最新的）
        if other.last_modified_date and (not self.last_modified_date or 
                                       other.last_modified_date > self.last_modified_date):
            self.last_modified_date = other.last_modified_date
        
        # 合并CVSS评分（优先使用v3）
        if other.cvss_v3 and not self.cvss_v3:
            self.cvss_v3 = other.cvss_v3
        if other.cvss_v2 and not self.cvss_v2:
            self.cvss_v2 = other.cvss_v2
        
        # 合并受影响的包
        existing_packages = {pkg.name: pkg for pkg in self.affected_packages}
        for other_pkg in other.affected_packages:
            if other_pkg.name not in existing_packages:
                self.affected_packages.append(other_pkg)
        
        # 合并参考链接
        existing_refs = {ref.url for ref in self.references}
        for other_ref in other.references:
            if other_ref.url not in existing_refs:
                self.references.append(other_ref)
                existing_refs.add(other_ref.url)
        
        # 合并补丁信息
        existing_patches = {patch['url'] for patch in self.patches}
        for other_patch in other.patches:
            if other_patch['url'] not in existing_patches:
                self.patches.append(other_patch)
        
        # 合并注释
        self.notes.extend([note for note in other.notes if note not in self.notes])
        
        # 保留原始数据
        self.raw_data.update(other.raw_data) 