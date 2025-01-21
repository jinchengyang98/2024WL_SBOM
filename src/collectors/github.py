#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GitHub安全公告采集器模块

实现了从GitHub Security Advisory采集漏洞数据的功能。
使用GitHub GraphQL API v4。
API文档：https://docs.github.com/en/graphql
"""

from datetime import datetime
from typing import Dict, List, Any
import logging

from .base import BaseVulnerabilityCollector

logger = logging.getLogger(__name__)

class GitHubCollector(BaseVulnerabilityCollector):
    """
    GitHub安全公告采集器
    
    通过GitHub GraphQL API获取安全公告数据。
    支持按时间范围查询和增量更新。
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化GitHub采集器
        
        Args:
            config: 配置信息，除基类配置外，还可包含：
                - per_page: 每页结果数（默认100）
        """
        super().__init__(config)
        self.per_page = config.get('per_page', 100)
        
        # GraphQL API端点
        self.url = 'https://api.github.com/graphql'
        
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        获取指定时间范围内的GitHub安全公告数据
        
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
        cursor = None
        
        try:
            while True:
                # 构建GraphQL查询
                query = self._build_graphql_query(
                    start_date=start_date,
                    end_date=end_date,
                    cursor=cursor,
                    per_page=self.per_page
                )
                
                # 发送API请求
                response_data = self.make_api_request(
                    endpoint='',
                    method='POST',
                    headers={'Accept': 'application/vnd.github.v4+json'},
                    data={'query': query}
                )
                
                # 提取安全公告数据
                data = response_data.get('data', {})
                advisories = data.get('securityAdvisories', {}).get('nodes', [])
                if not advisories:
                    break
                    
                # 清理并添加数据
                for advisory in advisories:
                    cleaned_data = self.clean_data(advisory)
                    all_advisories.append(cleaned_data)
                
                # 检查是否还有更多数据
                page_info = data.get('securityAdvisories', {}).get('pageInfo', {})
                if not page_info.get('hasNextPage'):
                    break
                    
                cursor = page_info.get('endCursor')
                logger.info(f"已获取 {len(all_advisories)} 条安全公告数据")
                
            logger.info(f"GitHub数据采集完成，共获取 {len(all_advisories)} 条安全公告数据")
            return all_advisories
            
        except Exception as e:
            self.handle_error(e, "获取GitHub数据失败")
            return []
            
    def _build_graphql_query(self, start_date: datetime, end_date: datetime, 
                           cursor: str = None, per_page: int = 100) -> str:
        """
        构建GraphQL查询语句
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            cursor: 分页游标
            per_page: 每页结果数
            
        Returns:
            GraphQL查询语句
        """
        after = f'after: "{cursor}"' if cursor else ''
        query = f'''
        {{
          securityAdvisories(first: {per_page} {after}
            orderBy: {{field: PUBLISHED_AT, direction: ASC}}
            publishedSince: "{start_date.isoformat()}Z"
            publishedBefore: "{end_date.isoformat()}Z"
          ) {{
            pageInfo {{
              hasNextPage
              endCursor
            }}
            nodes {{
              ghsaId
              summary
              description
              severity
              publishedAt
              updatedAt
              withdrawnAt
              references {{
                url
              }}
              identifiers {{
                type
                value
              }}
              vulnerabilities(first: 10) {{
                nodes {{
                  package {{
                    ecosystem
                    name
                  }}
                  firstPatchedVersion {{
                    identifier
                  }}
                  vulnerableVersionRange
                }}
              }}
            }}
          }}
        }}
        '''
        return query
        
    def clean_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        清理和标准化GitHub安全公告数据
        
        Args:
            data: 原始GitHub数据
            
        Returns:
            清理后的数据
        """
        try:
            # 提取基本信息
            cleaned = {
                'source': 'GitHub',
                'id': data.get('ghsaId'),
                'summary': data.get('summary'),
                'description': data.get('description'),
                'severity': data.get('severity'),
                'published_date': data.get('publishedAt'),
                'updated_date': data.get('updatedAt'),
                'withdrawn_date': data.get('withdrawnAt'),
                
                # 提取参考链接
                'references': [
                    {'url': ref.get('url')}
                    for ref in data.get('references', [])
                ],
                
                # 提取标识符
                'identifiers': [
                    {
                        'type': ident.get('type'),
                        'value': ident.get('value')
                    }
                    for ident in data.get('identifiers', [])
                ],
                
                # 提取受影响的包信息
                'affected_packages': self._extract_affected_packages(data),
                
                # 原始数据
                'raw_data': data
            }
            
            return cleaned
            
        except Exception as e:
            logger.error(f"清理GitHub数据失败: {str(e)}")
            return data
            
    def _extract_affected_packages(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """提取受影响的包信息"""
        vulnerabilities = data.get('vulnerabilities', {}).get('nodes', [])
        packages = []
        
        for vuln in vulnerabilities:
            package = vuln.get('package', {})
            first_patched = vuln.get('firstPatchedVersion', {})
            
            packages.append({
                'ecosystem': package.get('ecosystem'),
                'name': package.get('name'),
                'vulnerable_version_range': vuln.get('vulnerableVersionRange'),
                'first_patched_version': first_patched.get('identifier')
            })
            
        return packages 