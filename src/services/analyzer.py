#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据分析服务模块

负责对漏洞数据进行分析，支持：
1. 趋势分析
2. 关联分析
3. 影响分析
4. 统计分析
5. 风险评估
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import pandas as pd
import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from ..models.database import Database
from ..models.entities import Vulnerability, Package
from ..utils.logger import logger

class AnalyzerService:
    """数据分析服务"""
    
    def __init__(self,
                db_url: str = "sqlite:///data/vulnerabilities.db",
                min_similarity: float = 0.8):
        """
        初始化分析服务
        
        Args:
            db_url: 数据库连接URL
            min_similarity: 最小相似度阈值
        """
        self.db = Database(db_url)
        self.min_similarity = min_similarity
        self.vectorizer = TfidfVectorizer(
            stop_words='english',
            max_features=5000,
            ngram_range=(1, 2)
        )
    
    def analyze_trends(self,
                     start_date: datetime,
                     end_date: datetime,
                     interval: str = 'D',
                     source: Optional[str] = None) -> Dict[str, Any]:
        """
        分析漏洞趋势
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            interval: 时间间隔（D=日, W=周, M=月）
            source: 数据源
            
        Returns:
            趋势分析结果
        """
        # 获取时间范围内的漏洞数据
        vulns = self.db.get_vulnerabilities(source, start_date, end_date)
        
        # 创建时间序列数据
        dates = [v.published_date for v in vulns if v.published_date]
        severity_counts = defaultdict(list)
        
        # 按严重程度分组
        for vuln in vulns:
            if vuln.published_date and vuln.severity:
                severity_counts[vuln.severity].append(vuln.published_date)
        
        # 创建时间序列
        df = pd.DataFrame()
        
        # 总体趋势
        df['total'] = pd.Series(dates).value_counts().resample(interval).sum()
        
        # 按严重程度的趋势
        for severity, dates in severity_counts.items():
            df[severity.lower()] = pd.Series(dates).value_counts().resample(interval).sum()
        
        # 计算统计信息
        stats = {
            'total_count': len(vulns),
            'severity_distribution': {
                severity: len(dates)
                for severity, dates in severity_counts.items()
            },
            'daily_average': len(vulns) / (end_date - start_date).days,
            'time_series': df.fillna(0).to_dict()
        }
        
        return stats
    
    def analyze_correlations(self,
                          start_date: Optional[datetime] = None,
                          end_date: Optional[datetime] = None,
                          source: Optional[str] = None) -> Dict[str, Any]:
        """
        分析漏洞关联关系
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            source: 数据源
            
        Returns:
            关联分析结果
        """
        # 获取漏洞数据
        vulns = self.db.get_vulnerabilities(source, start_date, end_date)
        
        # 创建漏洞描述矩阵
        descriptions = [
            v.description for v in vulns 
            if v.description and len(v.description.split()) > 3
        ]
        
        if not descriptions:
            return {
                'similar_groups': [],
                'package_graph': {'nodes': [], 'edges': []}
            }
        
        # 计算文本相似度
        try:
            tfidf_matrix = self.vectorizer.fit_transform(descriptions)
            similarity_matrix = cosine_similarity(tfidf_matrix)
            
            # 查找相似的漏洞组
            similar_groups = []
            used_indices = set()
            
            for i in range(len(descriptions)):
                if i in used_indices:
                    continue
                    
                # 找到相似的漏洞
                similar_indices = []
                for j in range(len(descriptions)):
                    if i != j and similarity_matrix[i][j] >= self.min_similarity:
                        similar_indices.append(j)
                        
                if similar_indices:
                    group = [vulns[i]] + [vulns[j] for j in similar_indices]
                    similar_groups.append(group)
                    used_indices.add(i)
                    used_indices.update(similar_indices)
        except Exception as e:
            logger.error(f"Failed to compute text similarity: {str(e)}")
            similar_groups = []
        
        # 构建包依赖图
        graph = nx.Graph()
        
        # 添加节点和边
        for vuln in vulns:
            for pkg in vuln.affected_packages:
                # 添加包节点
                if not graph.has_node(pkg.name):
                    graph.add_node(pkg.name, type='package')
                
                # 添加生态系统节点
                if pkg.ecosystem and not graph.has_node(pkg.ecosystem):
                    graph.add_node(pkg.ecosystem, type='ecosystem')
                    graph.add_edge(pkg.name, pkg.ecosystem)
                
                # 添加平台节点
                if pkg.platform and not graph.has_node(pkg.platform):
                    graph.add_node(pkg.platform, type='platform')
                    graph.add_edge(pkg.name, pkg.platform)
        
        # 转换为可序列化的格式
        graph_data = {
            'nodes': [
                {'id': node, 'type': graph.nodes[node]['type']}
                for node in graph.nodes
            ],
            'edges': [
                {'source': u, 'target': v}
                for u, v in graph.edges
            ]
        }
        
        return {
            'similar_groups': [
                [v.id for v in group]
                for group in similar_groups
            ],
            'package_graph': graph_data
        }
    
    def analyze_impacts(self,
                      package_name: Optional[str] = None,
                      ecosystem: Optional[str] = None) -> Dict[str, Any]:
        """
        分析漏洞影响
        
        Args:
            package_name: 包名
            ecosystem: 生态系统
            
        Returns:
            影响分析结果
        """
        # 获取受影响的漏洞
        if package_name:
            vulns = self.db.get_affected_packages(package_name)
        else:
            vulns = self.db.get_vulnerabilities()
            if ecosystem:
                vulns = [
                    v for v in vulns
                    if any(p.ecosystem == ecosystem for p in v.affected_packages)
                ]
        
        if not vulns:
            return {
                'total_vulnerabilities': 0,
                'severity_distribution': {},
                'affected_versions': {},
                'fixed_versions': {},
                'impact_score': 0
            }
        
        # 统计严重程度分布
        severity_counts = Counter(v.severity for v in vulns if v.severity)
        
        # 统计受影响的版本
        affected_versions = defaultdict(int)
        fixed_versions = defaultdict(int)
        
        for vuln in vulns:
            for pkg in vuln.affected_packages:
                if package_name and pkg.name != package_name:
                    continue
                if ecosystem and pkg.ecosystem != ecosystem:
                    continue
                    
                for version in pkg.affected_versions:
                    affected_versions[version] += 1
                for version in pkg.fixed_versions:
                    fixed_versions[version] += 1
        
        # 计算影响得分
        # 基于CVSS评分的加权平均
        total_score = 0
        count = 0
        
        for vuln in vulns:
            if vuln.cvss_v3:
                total_score += vuln.cvss_v3.base_score
                count += 1
            elif vuln.cvss_v2:
                total_score += vuln.cvss_v2.base_score
                count += 1
                
        impact_score = total_score / count if count > 0 else 0
        
        return {
            'total_vulnerabilities': len(vulns),
            'severity_distribution': dict(severity_counts),
            'affected_versions': dict(affected_versions),
            'fixed_versions': dict(fixed_versions),
            'impact_score': round(impact_score, 2)
        }
    
    def analyze_statistics(self,
                        start_date: Optional[datetime] = None,
                        end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        生成统计分析报告
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            统计分析结果
        """
        # 获取漏洞数据
        vulns = self.db.get_vulnerabilities(None, start_date, end_date)
        
        if not vulns:
            return {
                'total_vulnerabilities': 0,
                'source_distribution': {},
                'severity_distribution': {},
                'ecosystem_distribution': {},
                'cvss_distribution': {'v2': {}, 'v3': {}},
                'top_affected_packages': [],
                'reference_statistics': {}
            }
        
        # 数据源分布
        source_counts = Counter(v.source for v in vulns)
        
        # 严重程度分布
        severity_counts = Counter(v.severity for v in vulns if v.severity)
        
        # 生态系统分布
        ecosystem_counts = Counter()
        for v in vulns:
            for pkg in v.affected_packages:
                if pkg.ecosystem:
                    ecosystem_counts[pkg.ecosystem] += 1
        
        # CVSS评分分布
        cvss_v2_scores = []
        cvss_v3_scores = []
        
        for v in vulns:
            if v.cvss_v2:
                cvss_v2_scores.append(v.cvss_v2.base_score)
            if v.cvss_v3:
                cvss_v3_scores.append(v.cvss_v3.base_score)
        
        # 计算CVSS评分区间分布
        def get_score_distribution(scores: List[float]) -> Dict[str, int]:
            dist = defaultdict(int)
            for score in scores:
                if score <= 3.9:
                    dist['0-3.9'] += 1
                elif score <= 6.9:
                    dist['4.0-6.9'] += 1
                elif score <= 8.9:
                    dist['7.0-8.9'] += 1
                else:
                    dist['9.0-10.0'] += 1
            return dict(dist)
        
        # 最常受影响的包
        package_counts = Counter()
        for v in vulns:
            for pkg in v.affected_packages:
                package_counts[pkg.name] += 1
        
        # 参考链接统计
        reference_counts = defaultdict(int)
        for v in vulns:
            for ref in v.references:
                if ref.source:
                    reference_counts[ref.source] += 1
        
        return {
            'total_vulnerabilities': len(vulns),
            'source_distribution': dict(source_counts),
            'severity_distribution': dict(severity_counts),
            'ecosystem_distribution': dict(ecosystem_counts),
            'cvss_distribution': {
                'v2': get_score_distribution(cvss_v2_scores),
                'v3': get_score_distribution(cvss_v3_scores)
            },
            'top_affected_packages': [
                {'name': name, 'count': count}
                for name, count in package_counts.most_common(10)
            ],
            'reference_statistics': dict(reference_counts)
        }
    
    def assess_risk(self,
                  package_name: str,
                  version: Optional[str] = None) -> Dict[str, Any]:
        """
        评估软件包的风险
        
        Args:
            package_name: 包名
            version: 版本号
            
        Returns:
            风险评估结果
        """
        # 获取影响该包的漏洞
        vulns = self.db.get_affected_packages(package_name)
        
        if not vulns:
            return {
                'risk_level': 'unknown',
                'risk_score': 0,
                'active_vulnerabilities': 0,
                'fixed_vulnerabilities': 0,
                'latest_vulnerability': None,
                'recommendation': 'No known vulnerabilities'
            }
        
        # 筛选特定版本的漏洞
        if version:
            version_vulns = []
            for vuln in vulns:
                for pkg in vuln.affected_packages:
                    if pkg.name == package_name and pkg.is_affected(version):
                        version_vulns.append(vuln)
            vulns = version_vulns
        
        # 计算风险得分
        total_score = 0
        max_score = 0
        active_count = 0
        fixed_count = 0
        latest_vuln = None
        
        for vuln in vulns:
            # 更新最新漏洞
            if not latest_vuln or (
                vuln.published_date and 
                latest_vuln.published_date and 
                vuln.published_date > latest_vuln.published_date
            ):
                latest_vuln = vuln
            
            # 检查是否已修复
            is_fixed = False
            for pkg in vuln.affected_packages:
                if pkg.name == package_name and pkg.fixed_versions:
                    is_fixed = True
                    break
            
            if is_fixed:
                fixed_count += 1
            else:
                active_count += 1
            
            # 计算得分
            score = 0
            if vuln.cvss_v3:
                score = vuln.cvss_v3.base_score
            elif vuln.cvss_v2:
                score = vuln.cvss_v2.base_score
            
            total_score += score
            max_score = max(max_score, score)
        
        # 计算平均风险得分
        risk_score = total_score / len(vulns) if vulns else 0
        
        # 确定风险等级
        if risk_score >= 7.0:
            risk_level = 'high'
        elif risk_score >= 4.0:
            risk_level = 'medium'
        elif risk_score > 0:
            risk_level = 'low'
        else:
            risk_level = 'unknown'
        
        # 生成建议
        if risk_level == 'high':
            recommendation = (
                "Immediate action recommended. Update to the latest version "
                "or implement security controls."
            )
        elif risk_level == 'medium':
            recommendation = (
                "Update recommended. Review and patch vulnerabilities "
                "based on your security policy."
            )
        elif risk_level == 'low':
            recommendation = (
                "Monitor for updates. Update during your regular "
                "maintenance window."
            )
        else:
            recommendation = (
                "No known vulnerabilities. Continue monitoring for "
                "new security advisories."
            )
        
        return {
            'risk_level': risk_level,
            'risk_score': round(risk_score, 2),
            'max_cvss_score': round(max_score, 2),
            'active_vulnerabilities': active_count,
            'fixed_vulnerabilities': fixed_count,
            'latest_vulnerability': latest_vuln.id if latest_vuln else None,
            'recommendation': recommendation
        }

"""
使用示例：

1. 趋势分析:
from services.analyzer import AnalyzerService
from datetime import datetime, timedelta

analyzer = AnalyzerService()

# 分析最近30天的趋势
end_date = datetime.now()
start_date = end_date - timedelta(days=30)
trends = analyzer.analyze_trends(start_date, end_date, interval='D')

2. 关联分析:
# 分析漏洞之间的关联关系
correlations = analyzer.analyze_correlations()

3. 影响分析:
# 分析特定包的影响
impacts = analyzer.analyze_impacts(package_name="lodash")

# 分析特定生态系统的影响
npm_impacts = analyzer.analyze_impacts(ecosystem="npm")

4. 统计分析:
# 生成统计报告
stats = analyzer.analyze_statistics()

5. 风险评估:
# 评估特定包的风险
risk = analyzer.assess_risk("lodash", version="4.17.15")
""" 