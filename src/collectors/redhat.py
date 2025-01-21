#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
RedHat漏洞数据采集器模块

实现了从RedHat Security Data API采集漏洞数据的功能。
API文档：https://access.redhat.com/documentation/en-us/red_hat_security_data_api/
"""

from datetime import datetime
from typing import Dict, List, Any
import logging

from .base import BaseVulnerabilityCollector

logger = logging.getLogger(__name__)

class RedHatCollector(BaseVulnerabilityCollector):
    """
    RedHat漏洞数据采集器
    
    通过RedHat Security Data API获取安全公告数据。
    支持按时间范围查询和增量更新。
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化RedHat采集器
        
        Args:
            config: 配置信息，除基类配置外，还可包含：
                - per_page: 每页结果数（默认100）
        """
        super().__init__(config)
        self.per_page = config.get('per_page', 100)
        
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        获取指定时间范围内的RedHat安全公告数据
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            包含漏洞信息的字典列表
            
        Raises:
            ValueError: 日期范围无效时
            RequestError: API请求失败时
        """
        # 验证日期范围
        self.validate_date_range(start_date, end_date)
        
        all_advisories = []
        page = 1
        
        try:
            while True:
                # 构建请求参数
                params = {
                    'after': start_date.strftime('%Y-%m-%d'),
                    'before': end_date.strftime('%Y-%m-%d'),
                    'per_page': self.per_page,
                    'page': page
                }
                
                # 发送API请求
                response_data = self.make_api_request(
                    endpoint='cves',
                    params=params
                )
                
                # 提取漏洞数据
                advisories = response_data.get('data', [])
                if not advisories:
                    break
                    
                # 清理并添加数据
                for advisory in advisories:
                    cleaned_data = self.clean_data(advisory)
                    all_advisories.append(cleaned_data)
                
                # 检查是否还有更多数据
                total_pages = response_data.get('pages', 1)
                if page >= total_pages:
                    break
                    
                page += 1
                logger.info(f"已获取 {len(all_advisories)} 条安全公告数据")
                
            logger.info(f"RedHat数据采集完成，共获取 {len(all_advisories)} 条安全公告数据")
            return all_advisories
            
        except Exception as e:
            self.handle_error(e, "获取RedHat数据失败")
            return []
            
    def clean_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        清理和标准化RedHat漏洞数据
        
        Args:
            data: 原始RedHat数据
            
        Returns:
            清理后的数据
        """
        try:
            # 提取基本信息
            cleaned = {
                'source': 'RedHat',
                'id': data.get('CVE'),
                'title': data.get('bugzilla_description'),
                'public_date': data.get('public_date'),
                'modified_date': data.get('modified_date'),
                'severity': data.get('severity'),
                'state': data.get('state'),
                
                # 提取CVSS评分
                'metrics': {
                    'cvss_v3': self._extract_cvss_v3(data),
                    'cvss_v2': self._extract_cvss_v2(data)
                },
                
                # 提取受影响的包信息
                'affected_packages': self._extract_affected_packages(data),
                
                # 提取参考链接
                'references': self._extract_references(data),
                
                # 提取修复信息
                'fixes': self._extract_fixes(data),
                
                # 原始数据
                'raw_data': data
            }
            
            return cleaned
            
        except Exception as e:
            logger.error(f"清理RedHat数据失败: {str(e)}")
            return data
            
    def _extract_cvss_v3(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """提取CVSS v3评分信息"""
        cvss3 = data.get('cvss3', {})
        return {
            'version': '3.0',
            'vector_string': cvss3.get('cvss3_scoring_vector'),
            'base_score': cvss3.get('cvss3_base_score'),
            'status': cvss3.get('status')
        } if cvss3 else {}
        
    def _extract_cvss_v2(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """提取CVSS v2评分信息"""
        cvss2 = data.get('cvss', {})
        return {
            'version': '2.0',
            'vector_string': cvss2.get('cvss_scoring_vector'),
            'base_score': cvss2.get('cvss_base_score'),
            'status': cvss2.get('status')
        } if cvss2 else {}
        
    def _extract_affected_packages(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取受影响的包信息"""
        packages = []
        for package in data.get('affected_packages', []):
            packages.append({
                'name': package.get('package_name'),
                'module': package.get('module_name'),
                'product': package.get('product_name'),
                'release': package.get('release'),
                'arch': package.get('arch'),
                'fix_state': package.get('fix_state')
            })
        return packages
        
    def _extract_references(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取参考链接"""
        references = []
        
        # 添加Bugzilla链接
        if data.get('bugzilla'):
            references.append({
                'type': 'bugzilla',
                'url': f"https://bugzilla.redhat.com/{data['bugzilla']}"
            })
            
        # 添加其他参考链接
        for ref in data.get('references', []):
            references.append({
                'type': 'other',
                'url': ref
            })
            
        return references
        
    def _extract_fixes(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取修复信息"""
        fixes = []
        for fix in data.get('fixes', []):
            fixes.append({
                'ticket': fix.get('ticket'),
                'state': fix.get('state'),
                'resolution': fix.get('resolution'),
                'release': fix.get('release')
            })
        return fixes 