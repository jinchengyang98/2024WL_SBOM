#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据清洗服务模块

负责对采集的漏洞数据进行清洗和标准化，支持：
1. 数据去重
2. 数据合并
3. 字段标准化
4. 数据验证
5. 数据修复
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor

from ..models.database import Database
from ..models.entities import Vulnerability, Package, Version, Reference
from ..utils.logger import logger

class CleanerService:
    """数据清洗服务"""
    
    def __init__(self,
                db_url: str = "sqlite:///data/vulnerabilities.db",
                max_workers: int = 4):
        """
        初始化清洗服务
        
        Args:
            db_url: 数据库连接URL
            max_workers: 最大工作线程数
        """
        self.db = Database(db_url)
        self.max_workers = max_workers
        
    def clean_description(self, desc: Optional[str]) -> Optional[str]:
        """
        清洗描述文本
        
        Args:
            desc: 原始描述文本
            
        Returns:
            清洗后的描述文本
        """
        if not desc:
            return None
            
        # 移除HTML标签
        desc = re.sub(r'<[^>]+>', '', desc)
        
        # 移除多余的空白字符
        desc = ' '.join(desc.split())
        
        # 移除不可打印字符
        desc = ''.join(char for char in desc if char.isprintable())
        
        return desc
    
    def clean_references(self, refs: List[Reference]) -> List[Reference]:
        """
        清洗参考链接
        
        Args:
            refs: 原始参考链接列表
            
        Returns:
            清洗后的参考链接列表
        """
        cleaned_refs = []
        seen_urls = set()
        
        for ref in refs:
            # 跳过空URL
            if not ref.url:
                continue
                
            # 规范化URL
            url = ref.url.strip().rstrip('/')
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            # 去重
            if url in seen_urls:
                continue
            seen_urls.add(url)
            
            # 更新URL
            ref.url = url
            cleaned_refs.append(ref)
            
        return cleaned_refs
    
    def clean_package(self, pkg: Package) -> Package:
        """
        清洗软件包信息
        
        Args:
            pkg: 原始软件包信息
            
        Returns:
            清洗后的软件包信息
        """
        # 规范化包名
        pkg.name = pkg.name.strip().lower()
        
        # 规范化生态系统名称
        if pkg.ecosystem:
            pkg.ecosystem = pkg.ecosystem.strip().lower()
        
        # 清理版本信息
        cleaned_versions = []
        seen_versions = set()
        
        for ver in pkg.versions:
            version = ver.version.strip()
            if version and version not in seen_versions:
                seen_versions.add(version)
                ver.version = version
                cleaned_versions.append(ver)
                
        pkg.versions = cleaned_versions
        
        # 清理受影响的版本
        pkg.affected_versions = list(set(v.strip() for v in pkg.affected_versions if v.strip()))
        
        # 清理修复版本
        pkg.fixed_versions = list(set(v.strip() for v in pkg.fixed_versions if v.strip()))
        
        return pkg
    
    def merge_vulnerabilities(self, vulns: List[Vulnerability]) -> Vulnerability:
        """
        合并多个漏洞记录
        
        Args:
            vulns: 漏洞记录列表
            
        Returns:
            合并后的漏洞记录
        """
        if not vulns:
            raise ValueError("Empty vulnerability list")
            
        # 使用第一个记录作为基础
        base = vulns[0]
        
        # 合并其他记录
        for vuln in vulns[1:]:
            base.merge(vuln)
            
        return base
    
    def clean_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        """
        清洗单个漏洞记录
        
        Args:
            vuln: 原始漏洞记录
            
        Returns:
            清洗后的漏洞记录
        """
        # 清洗描述
        vuln.description = self.clean_description(vuln.description)
        
        # 清洗参考链接
        vuln.references = self.clean_references(vuln.references)
        
        # 清洗受影响的包
        vuln.affected_packages = [
            self.clean_package(pkg)
            for pkg in vuln.affected_packages
        ]
        
        # 清洗补丁信息
        cleaned_patches = []
        seen_urls = set()
        
        for patch in vuln.patches:
            url = patch.get('url', '').strip()
            if url and url not in seen_urls:
                seen_urls.add(url)
                cleaned_patches.append(patch)
                
        vuln.patches = cleaned_patches
        
        # 清洗注释
        vuln.notes = [note.strip() for note in vuln.notes if note.strip()]
        
        return vuln
    
    def clean_all(self,
                start_date: Optional[datetime] = None,
                end_date: Optional[datetime] = None,
                source: Optional[str] = None) -> Dict[str, int]:
        """
        清洗指定范围内的所有漏洞数据
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            source: 数据源
            
        Returns:
            清洗统计信息
        """
        stats = {
            'total': 0,
            'cleaned': 0,
            'merged': 0,
            'failed': 0
        }
        
        try:
            # 获取需要清洗的漏洞数据
            vulns = self.db.get_vulnerabilities(source, start_date, end_date)
            stats['total'] = len(vulns)
            
            # 按ID分组
            vuln_groups: Dict[str, List[Vulnerability]] = {}
            for vuln in vulns:
                vuln_groups.setdefault(vuln.id, []).append(vuln)
            
            # 清洗和合并每组漏洞
            for vuln_id, group in vuln_groups.items():
                try:
                    # 清洗每条记录
                    cleaned_group = [self.clean_vulnerability(v) for v in group]
                    stats['cleaned'] += len(cleaned_group)
                    
                    # 如果有多条记录，进行合并
                    if len(cleaned_group) > 1:
                        merged = self.merge_vulnerabilities(cleaned_group)
                        stats['merged'] += 1
                        
                        # 更新数据库
                        self.db.update_vulnerability(merged)
                    else:
                        # 更新数据库
                        self.db.update_vulnerability(cleaned_group[0])
                        
                except Exception as e:
                    logger.error(f"Failed to clean vulnerability {vuln_id}: {str(e)}")
                    stats['failed'] += 1
            
            logger.info(f"Cleaning completed: {stats}")
            
        except Exception as e:
            logger.error(f"Failed to clean vulnerabilities: {str(e)}")
            raise
            
        return stats

"""
使用示例：

1. 基本用法:
from services.cleaner import CleanerService

# 创建清洗服务实例
service = CleanerService()

# 清洗所有数据
stats = service.clean_all()
print(f"Cleaning statistics: {stats}")

2. 清洗指定时间范围的数据:
from datetime import datetime

# 指定日期范围
start_date = datetime(2024, 1, 1)
end_date = datetime(2024, 1, 31)

# 清洗指定范围的数据
stats = service.clean_all(start_date, end_date)

3. 清洗指定数据源的数据:
# 只清洗NVD数据
stats = service.clean_all(source='nvd')

4. 单独使用清洗功能:
from models.entities import Vulnerability, Package, Reference

# 清洗描述
cleaned_desc = service.clean_description("原始描述<b>带HTML标签</b>")

# 清洗软件包
pkg = Package(name="Test-Package", ecosystem="NPM")
cleaned_pkg = service.clean_package(pkg)

# 清洗参考链接
refs = [Reference(url="example.com/vuln1"), Reference(url="http://example.com/vuln1")]
cleaned_refs = service.clean_references(refs)  # 会去重
""" 