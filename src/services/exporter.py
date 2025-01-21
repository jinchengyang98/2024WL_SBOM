#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据导出服务模块

负责将漏洞数据导出为各种格式，支持：
1. JSON导出
2. CSV导出
3. Excel导出
4. HTML报告
5. Markdown报告
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import json
import pandas as pd
import jinja2
from markdown2 import Markdown

from ..models.database import Database
from ..models.entities import Vulnerability
from ..utils.logger import logger
from ..utils.file import FileHandler, SafeFileHandler

class ExporterService:
    """数据导出服务"""
    
    def __init__(self,
                db_url: str = "sqlite:///data/vulnerabilities.db",
                template_dir: str = "templates",
                output_dir: str = "exports"):
        """
        初始化导出服务
        
        Args:
            db_url: 数据库连接URL
            template_dir: 模板目录
            output_dir: 输出目录
        """
        self.db = Database(db_url)
        self.template_dir = template_dir
        self.output_dir = output_dir
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        # 初始化模板引擎
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=True
        )
        
        # 初始化Markdown转换器
        self.markdown = Markdown(extras=['tables', 'fenced-code-blocks'])
    
    def _prepare_vulnerability_data(self,
                                vulns: List[Vulnerability]) -> List[Dict]:
        """
        准备漏洞数据用于导出
        
        Args:
            vulns: 漏洞列表
            
        Returns:
            处理后的数据列表
        """
        data = []
        
        for vuln in vulns:
            # 基本信息
            item = {
                'id': vuln.id,
                'source': vuln.source,
                'title': vuln.title,
                'description': vuln.description,
                'published_date': vuln.published_date.isoformat() if vuln.published_date else None,
                'last_modified_date': vuln.last_modified_date.isoformat() if vuln.last_modified_date else None,
                'severity': vuln.severity,
                'status': vuln.status
            }
            
            # CVSS评分
            if vuln.cvss_v3:
                item['cvss_v3_score'] = vuln.cvss_v3.base_score
                item['cvss_v3_vector'] = vuln.cvss_v3.vector_string
            if vuln.cvss_v2:
                item['cvss_v2_score'] = vuln.cvss_v2.base_score
                item['cvss_v2_vector'] = vuln.cvss_v2.vector_string
            
            # 受影响的包
            item['affected_packages'] = []
            for pkg in vuln.affected_packages:
                pkg_info = {
                    'name': pkg.name,
                    'ecosystem': pkg.ecosystem,
                    'platform': pkg.platform,
                    'affected_versions': pkg.affected_versions,
                    'fixed_versions': pkg.fixed_versions
                }
                item['affected_packages'].append(pkg_info)
            
            # 参考链接
            item['references'] = [
                {
                    'url': ref.url,
                    'source': ref.source,
                    'type': ref.type
                }
                for ref in vuln.references
            ]
            
            data.append(item)
            
        return data
    
    def export_json(self,
                  start_date: Optional[datetime] = None,
                  end_date: Optional[datetime] = None,
                  source: Optional[str] = None,
                  output_file: Optional[str] = None) -> str:
        """
        导出为JSON格式
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            source: 数据源
            output_file: 输出文件路径
            
        Returns:
            输出文件路径
        """
        # 获取漏洞数据
        vulns = self.db.get_vulnerabilities(source, start_date, end_date)
        data = self._prepare_vulnerability_data(vulns)
        
        # 生成输出文件路径
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.output_dir, f'vulnerabilities_{timestamp}.json')
        
        # 安全写入文件
        SafeFileHandler.safe_write(
            output_file,
            FileHandler.write_json,
            data
        )
        
        logger.info(f"Exported {len(data)} vulnerabilities to {output_file}")
        return output_file
    
    def export_csv(self,
                 start_date: Optional[datetime] = None,
                 end_date: Optional[datetime] = None,
                 source: Optional[str] = None,
                 output_file: Optional[str] = None) -> str:
        """
        导出为CSV格式
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            source: 数据源
            output_file: 输出文件路径
            
        Returns:
            输出文件路径
        """
        # 获取漏洞数据
        vulns = self.db.get_vulnerabilities(source, start_date, end_date)
        data = self._prepare_vulnerability_data(vulns)
        
        # 展平数据结构
        flattened_data = []
        for item in data:
            # 基本字段
            flat_item = {
                'id': item['id'],
                'source': item['source'],
                'title': item['title'],
                'description': item['description'],
                'published_date': item['published_date'],
                'last_modified_date': item['last_modified_date'],
                'severity': item['severity'],
                'status': item['status'],
                'cvss_v3_score': item.get('cvss_v3_score'),
                'cvss_v3_vector': item.get('cvss_v3_vector'),
                'cvss_v2_score': item.get('cvss_v2_score'),
                'cvss_v2_vector': item.get('cvss_v2_vector')
            }
            
            # 受影响的包
            packages = item['affected_packages']
            if packages:
                flat_item.update({
                    'package_name': packages[0]['name'],
                    'package_ecosystem': packages[0]['ecosystem'],
                    'package_platform': packages[0]['platform'],
                    'affected_versions': ', '.join(packages[0]['affected_versions']),
                    'fixed_versions': ', '.join(packages[0]['fixed_versions'])
                })
            
            # 参考链接
            references = item['references']
            if references:
                flat_item['reference_urls'] = ', '.join(ref['url'] for ref in references)
            
            flattened_data.append(flat_item)
        
        # 生成输出文件路径
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.output_dir, f'vulnerabilities_{timestamp}.csv')
        
        # 安全写入文件
        SafeFileHandler.safe_write(
            output_file,
            FileHandler.write_csv,
            flattened_data
        )
        
        logger.info(f"Exported {len(data)} vulnerabilities to {output_file}")
        return output_file
    
    def export_excel(self,
                   start_date: Optional[datetime] = None,
                   end_date: Optional[datetime] = None,
                   source: Optional[str] = None,
                   output_file: Optional[str] = None) -> str:
        """
        导出为Excel格式
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            source: 数据源
            output_file: 输出文件路径
            
        Returns:
            输出文件路径
        """
        # 获取漏洞数据
        vulns = self.db.get_vulnerabilities(source, start_date, end_date)
        data = self._prepare_vulnerability_data(vulns)
        
        # 创建Excel writer
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.output_dir, f'vulnerabilities_{timestamp}.xlsx')
        
        # 创建数据框
        df_vulns = pd.DataFrame([
            {
                'ID': item['id'],
                'Source': item['source'],
                'Title': item['title'],
                'Severity': item['severity'],
                'Status': item['status'],
                'Published Date': item['published_date'],
                'CVSS v3': item.get('cvss_v3_score'),
                'CVSS v2': item.get('cvss_v2_score')
            }
            for item in data
        ])
        
        # 创建受影响包的数据框
        packages_data = []
        for item in data:
            vuln_id = item['id']
            for pkg in item['affected_packages']:
                packages_data.append({
                    'Vulnerability ID': vuln_id,
                    'Package Name': pkg['name'],
                    'Ecosystem': pkg['ecosystem'],
                    'Platform': pkg['platform'],
                    'Affected Versions': ', '.join(pkg['affected_versions']),
                    'Fixed Versions': ', '.join(pkg['fixed_versions'])
                })
        df_packages = pd.DataFrame(packages_data)
        
        # 创建参考链接的数据框
        references_data = []
        for item in data:
            vuln_id = item['id']
            for ref in item['references']:
                references_data.append({
                    'Vulnerability ID': vuln_id,
                    'URL': ref['url'],
                    'Source': ref['source'],
                    'Type': ref['type']
                })
        df_references = pd.DataFrame(references_data)
        
        # 写入Excel文件
        with pd.ExcelWriter(output_file) as writer:
            df_vulns.to_excel(writer, sheet_name='Vulnerabilities', index=False)
            df_packages.to_excel(writer, sheet_name='Affected Packages', index=False)
            df_references.to_excel(writer, sheet_name='References', index=False)
        
        logger.info(f"Exported {len(data)} vulnerabilities to {output_file}")
        return output_file
    
    def export_html(self,
                  start_date: Optional[datetime] = None,
                  end_date: Optional[datetime] = None,
                  source: Optional[str] = None,
                  template: str = "report.html",
                  output_file: Optional[str] = None) -> str:
        """
        导出为HTML报告
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            source: 数据源
            template: 模板文件名
            output_file: 输出文件路径
            
        Returns:
            输出文件路径
        """
        # 获取漏洞数据
        vulns = self.db.get_vulnerabilities(source, start_date, end_date)
        data = self._prepare_vulnerability_data(vulns)
        
        # 生成输出文件路径
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.output_dir, f'report_{timestamp}.html')
        
        try:
            # 加载模板
            template = self.jinja_env.get_template(template)
            
            # 渲染HTML
            html = template.render(
                vulnerabilities=data,
                generated_at=datetime.now().isoformat(),
                total_count=len(data)
            )
            
            # 写入文件
            SafeFileHandler.safe_write(
                output_file,
                FileHandler.write_text,
                html
            )
            
            logger.info(f"Exported HTML report to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    def export_markdown(self,
                      start_date: Optional[datetime] = None,
                      end_date: Optional[datetime] = None,
                      source: Optional[str] = None,
                      template: str = "report.md",
                      output_file: Optional[str] = None) -> str:
        """
        导出为Markdown报告
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            source: 数据源
            template: 模板文件名
            output_file: 输出文件路径
            
        Returns:
            输出文件路径
        """
        # 获取漏洞数据
        vulns = self.db.get_vulnerabilities(source, start_date, end_date)
        data = self._prepare_vulnerability_data(vulns)
        
        # 生成输出文件路径
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.output_dir, f'report_{timestamp}.md')
        
        try:
            # 加载模板
            template = self.jinja_env.get_template(template)
            
            # 渲染Markdown
            markdown = template.render(
                vulnerabilities=data,
                generated_at=datetime.now().isoformat(),
                total_count=len(data)
            )
            
            # 写入文件
            SafeFileHandler.safe_write(
                output_file,
                FileHandler.write_text,
                markdown
            )
            
            logger.info(f"Exported Markdown report to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {str(e)}")
            raise

"""
使用示例：

1. 导出为JSON:
from services.exporter import ExporterService
from datetime import datetime, timedelta

exporter = ExporterService()

# 导出最近30天的数据
end_date = datetime.now()
start_date = end_date - timedelta(days=30)
json_file = exporter.export_json(start_date, end_date)

2. 导出为CSV:
# 导出指定数据源的数据
csv_file = exporter.export_csv(source='nvd')

3. 导出为Excel:
# 导出所有数据
excel_file = exporter.export_excel()

4. 生成HTML报告:
# 使用自定义模板
html_file = exporter.export_html(template='custom_report.html')

5. 生成Markdown报告:
# 指定输出文件
md_file = exporter.export_markdown(output_file='vulnerability_report.md')

6. 模板示例:

HTML模板 (templates/report.html):
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
</head>
<body>
    <h1>Vulnerability Report</h1>
    <p>Generated at: {{ generated_at }}</p>
    <p>Total vulnerabilities: {{ total_count }}</p>
    
    {% for vuln in vulnerabilities %}
    <div class="vulnerability">
        <h2>{{ vuln.id }}</h2>
        <p>Severity: {{ vuln.severity }}</p>
        <p>{{ vuln.description }}</p>
    </div>
    {% endfor %}
</body>
</html>

Markdown模板 (templates/report.md):
# Vulnerability Report

Generated at: {{ generated_at }}
Total vulnerabilities: {{ total_count }}

{% for vuln in vulnerabilities %}
## {{ vuln.id }}

- Severity: {{ vuln.severity }}
- Published: {{ vuln.published_date }}

### Description

{{ vuln.description }}

### Affected Packages

{% for pkg in vuln.affected_packages %}
- {{ pkg.name }} ({{ pkg.ecosystem }})
  - Affected versions: {{ pkg.affected_versions|join(', ') }}
  - Fixed versions: {{ pkg.fixed_versions|join(', ') }}
{% endfor %}

{% endfor %}
""" 