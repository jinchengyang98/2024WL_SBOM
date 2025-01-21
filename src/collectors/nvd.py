#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
NVD漏洞数据采集器模块

实现了从美国国家漏洞数据库(NVD)采集漏洞数据的功能。
使用NVD REST API 2.0版本。
API文档：https://nvd.nist.gov/developers/vulnerabilities
"""

from datetime import datetime
from typing import Dict, List, Any
import logging

from .base import BaseVulnerabilityCollector

logger = logging.getLogger(__name__)

class NVDCollector(BaseVulnerabilityCollector):
    """
    NVD漏洞数据采集器
    
    通过NVD REST API获取CVE漏洞数据。
    支持按时间范围查询和增量更新。
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化NVD采集器
        
        Args:
            config: 配置信息，除基类配置外，还可包含：
                - results_per_page: 每页结果数（默认2000）
        """
        super().__init__(config)
        self.results_per_page = config.get('results_per_page', 2000)
        
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        获取指定时间范围内的NVD漏洞数据
        
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
        
        all_vulnerabilities = []
        start_index = 0
        
        try:
            while True:
                # 构建请求参数
                params = {
                    'lastModStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'lastModEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.999'),
                    'resultsPerPage': self.results_per_page,
                    'startIndex': start_index
                }
                
                # 发送API请求
                response_data = self.make_api_request(
                    endpoint='vulnerabilities',
                    params=params
                )
                
                # 提取漏洞数据
                vulnerabilities = response_data.get('vulnerabilities', [])
                if not vulnerabilities:
                    break
                    
                # 清理并添加数据
                for vuln in vulnerabilities:
                    cleaned_data = self.clean_data(vuln)
                    all_vulnerabilities.append(cleaned_data)
                
                # 检查是否还有更多数据
                total_results = response_data.get('totalResults', 0)
                if start_index + len(vulnerabilities) >= total_results:
                    break
                    
                start_index += len(vulnerabilities)
                logger.info(f"已获取 {len(all_vulnerabilities)}/{total_results} 条漏洞数据")
                
            logger.info(f"NVD数据采集完成，共获取 {len(all_vulnerabilities)} 条漏洞数据")
            return all_vulnerabilities
            
        except Exception as e:
            self.handle_error(e, "获取NVD数据失败")
            return []
            
    def clean_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        清理和标准化NVD漏洞数据
        
        Args:
            data: 原始NVD数据
            
        Returns:
            清理后的数据
        """
        try:
            cve = data.get('cve', {})
            
            # 提取基本信息
            cleaned = {
                'source': 'NVD',
                'id': cve.get('id'),
                'published_date': cve.get('published'),
                'last_modified_date': cve.get('lastModified'),
                'vuln_status': cve.get('vulnStatus'),
                
                # 提取描述
                'descriptions': [
                    {
                        'lang': desc.get('lang'),
                        'value': desc.get('value')
                    }
                    for desc in cve.get('descriptions', [])
                ],
                
                # 提取参考链接
                'references': [
                    {
                        'url': ref.get('url'),
                        'source': ref.get('source'),
                        'tags': ref.get('tags', [])
                    }
                    for ref in cve.get('references', [])
                ],
                
                # 提取CVSS评分
                'metrics': {
                    'cvss_v3': self._extract_cvss_v3(cve),
                    'cvss_v2': self._extract_cvss_v2(cve)
                },
                
                # 提取受影响的产品配置
                'configurations': cve.get('configurations', []),
                
                # 原始数据
                'raw_data': data
            }
            
            return cleaned
            
        except Exception as e:
            logger.error(f"清理NVD数据失败: {str(e)}")
            return data
            
    def _extract_cvss_v3(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """提取CVSS v3评分信息"""
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [])  # 优先使用v3.1
        if not cvss_v3:
            cvss_v3 = metrics.get('cvssMetricV30', [])
            
        if cvss_v3:
            cvss_data = cvss_v3[0].get('cvssData', {})
            return {
                'version': cvss_data.get('version'),
                'vector_string': cvss_data.get('vectorString'),
                'base_score': cvss_data.get('baseScore'),
                'base_severity': cvss_data.get('baseSeverity'),
                'exploitability_score': cvss_v3[0].get('exploitabilityScore'),
                'impact_score': cvss_v3[0].get('impactScore')
            }
        return {}
        
    def _extract_cvss_v2(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        """提取CVSS v2评分信息"""
        metrics = cve.get('metrics', {})
        cvss_v2 = metrics.get('cvssMetricV2', [])
        
        if cvss_v2:
            cvss_data = cvss_v2[0].get('cvssData', {})
            return {
                'version': '2.0',
                'vector_string': cvss_data.get('vectorString'),
                'base_score': cvss_data.get('baseScore'),
                'exploitability_score': cvss_v2[0].get('exploitabilityScore'),
                'impact_score': cvss_v2[0].get('impactScore'),
                'severity': cvss_v2[0].get('baseSeverity')
            }
        return {} 