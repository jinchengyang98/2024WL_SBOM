#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Debian漏洞数据采集器模块

实现了从Debian Security Tracker采集漏洞数据的功能。
数据源：https://security-tracker.debian.org/tracker/
"""

from datetime import datetime
from typing import Dict, List, Any
import logging
import json
from bs4 import BeautifulSoup

from .base import BaseVulnerabilityCollector

logger = logging.getLogger(__name__)

class DebianCollector(BaseVulnerabilityCollector):
    """
    Debian漏洞数据采集器
    
    通过Debian Security Tracker获取漏洞数据。
    支持按时间范围查询和增量更新。
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化Debian采集器
        
        Args:
            config: 配置信息，除基类配置外，还可包含：
                - releases: 要获取的Debian版本列表（默认为["buster", "bullseye", "bookworm"]）
        """
        super().__init__(config)
        self.releases = config.get('releases', ["buster", "bullseye", "bookworm"])
        
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        获取指定时间范围内的Debian漏洞数据
        
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
        
        try:
            # 获取JSON格式的漏洞数据
            response_data = self.make_api_request(
                endpoint='json',
                headers={'Accept': 'application/json'}
            )
            
            # 处理每个发行版的数据
            for release in self.releases:
                release_data = response_data.get(release, {})
                for pkg_name, pkg_data in release_data.items():
                    # 提取漏洞信息
                    for vuln_id, vuln_data in pkg_data.get('vulnerabilities', {}).items():
                        # 检查时间范围
                        if not self._is_in_date_range(vuln_data, start_date, end_date):
                            continue
                            
                        # 获取详细信息
                        detailed_data = self._fetch_vulnerability_details(vuln_id)
                        
                        # 合并数据
                        merged_data = {
                            'release': release,
                            'package': pkg_name,
                            **vuln_data,
                            **detailed_data
                        }
                        
                        # 清理数据
                        cleaned_data = self.clean_data(merged_data)
                        all_vulnerabilities.append(cleaned_data)
                        
            logger.info(f"Debian数据采集完成，共获取 {len(all_vulnerabilities)} 条漏洞数据")
            return all_vulnerabilities
            
        except Exception as e:
            self.handle_error(e, "获取Debian数据失败")
            return []
            
    def _is_in_date_range(self, data: Dict[str, Any], start_date: datetime, end_date: datetime) -> bool:
        """检查漏洞是否在指定时间范围内"""
        # 获取漏洞的发布时间或最后修改时间
        vuln_date = data.get('last_modified') or data.get('discovered')
        if not vuln_date:
            return False
            
        try:
            vuln_datetime = datetime.strptime(vuln_date, '%Y-%m-%d')
            return start_date <= vuln_datetime <= end_date
        except ValueError:
            return False
            
    def _fetch_vulnerability_details(self, vuln_id: str) -> Dict[str, Any]:
        """获取漏洞的详细信息"""
        try:
            # 获取HTML格式的详细信息
            response = self.make_api_request(
                endpoint=f'data/{vuln_id}',
                headers={'Accept': 'text/html'}
            )
            
            # 解析HTML内容
            soup = BeautifulSoup(response.get('content', ''), 'html.parser')
            
            # 提取详细信息
            details = {
                'description': self._extract_description(soup),
                'references': self._extract_references(soup),
                'patches': self._extract_patches(soup),
                'notes': self._extract_notes(soup)
            }
            
            return details
            
        except Exception as e:
            logger.warning(f"获取漏洞 {vuln_id} 的详细信息失败: {str(e)}")
            return {}
            
    def clean_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        清理和标准化Debian漏洞数据
        
        Args:
            data: 原始Debian数据
            
        Returns:
            清理后的数据
        """
        try:
            # 提取基本信息
            cleaned = {
                'source': 'Debian',
                'id': data.get('id'),
                'package': data.get('package'),
                'release': data.get('release'),
                'status': data.get('status'),
                'urgency': data.get('urgency'),
                'discovered_date': data.get('discovered'),
                'modified_date': data.get('last_modified'),
                
                # 提取描述和影响
                'description': data.get('description'),
                'scope': data.get('scope'),
                
                # 提取版本信息
                'fixed_version': data.get('fixed_version'),
                'affected_versions': self._extract_affected_versions(data),
                
                # 提取参考信息
                'references': data.get('references', []),
                'patches': data.get('patches', []),
                'notes': data.get('notes', []),
                
                # 原始数据
                'raw_data': data
            }
            
            return cleaned
            
        except Exception as e:
            logger.error(f"清理Debian数据失败: {str(e)}")
            return data
            
    def _extract_description(self, soup: BeautifulSoup) -> str:
        """从HTML中提取漏洞描述"""
        desc_elem = soup.find('div', class_='description')
        return desc_elem.get_text().strip() if desc_elem else ''
        
    def _extract_references(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """从HTML中提取参考链接"""
        refs = []
        ref_list = soup.find('div', class_='references')
        if ref_list:
            for link in ref_list.find_all('a'):
                refs.append({
                    'type': self._guess_reference_type(link['href']),
                    'url': link['href']
                })
        return refs
        
    def _extract_patches(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """从HTML中提取补丁信息"""
        patches = []
        patch_list = soup.find('div', class_='patches')
        if patch_list:
            for link in patch_list.find_all('a'):
                patches.append({
                    'name': link.get_text(),
                    'url': link['href']
                })
        return patches
        
    def _extract_notes(self, soup: BeautifulSoup) -> List[str]:
        """从HTML中提取注释信息"""
        notes = []
        notes_elem = soup.find('div', class_='notes')
        if notes_elem:
            for note in notes_elem.find_all('p'):
                notes.append(note.get_text().strip())
        return notes
        
    def _extract_affected_versions(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取受影响的版本信息"""
        versions = []
        for version_data in data.get('versions', []):
            versions.append({
                'version': version_data.get('version'),
                'repositories': version_data.get('repositories', []),
                'architectures': version_data.get('architectures', [])
            })
        return versions
        
    def _guess_reference_type(self, url: str) -> str:
        """根据URL猜测参考链接类型"""
        if 'cve.mitre.org' in url:
            return 'CVE'
        elif 'bugs.debian.org' in url:
            return 'Debian Bug'
        elif 'security-tracker.debian.org' in url:
            return 'Debian Security Tracker'
        elif 'github.com' in url:
            return 'GitHub'
        else:
            return 'Other' 