#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
漏洞数据采集服务模块

负责从多个数据源采集漏洞数据，支持：
1. 多源数据并行采集
2. 增量更新
3. 错误重试
4. 数据持久化
"""

import os
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from ..models.database import Database
from ..collectors.base import BaseVulnerabilityCollector
from ..collectors.nvd import NVDCollector
from ..collectors.github import GitHubCollector
from ..collectors.redhat import RedHatCollector
from ..collectors.debian import DebianCollector
from ..utils.logger import logger
from ..utils.file import FileHandler

class CollectorService:
    """漏洞数据采集服务"""
    
    def __init__(self,
                config_path: str = "config/sources.json",
                db_url: str = "sqlite:///data/vulnerabilities.db",
                max_workers: int = 4):
        """
        初始化采集服务
        
        Args:
            config_path: 配置文件路径
            db_url: 数据库连接URL
            max_workers: 最大工作线程数
        """
        self.config_path = config_path
        self.db = Database(db_url)
        self.max_workers = max_workers
        self.collectors: Dict[str, BaseVulnerabilityCollector] = {}
        
        # 加载配置
        self.load_config()
        
        # 初始化数据库
        self.db.create_tables()
        
    def load_config(self):
        """加载数据源配置"""
        try:
            config = FileHandler.read_json(self.config_path)
            
            # 初始化采集器
            if 'nvd' in config:
                self.collectors['nvd'] = NVDCollector(**config['nvd'])
            if 'github' in config:
                self.collectors['github'] = GitHubCollector(**config['github'])
            if 'redhat' in config:
                self.collectors['redhat'] = RedHatCollector(**config['redhat'])
            if 'debian' in config:
                self.collectors['debian'] = DebianCollector(**config['debian'])
                
            logger.info(f"Loaded collectors: {list(self.collectors.keys())}")
            
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
            raise
    
    async def collect_from_source(self,
                               source: str,
                               collector: BaseVulnerabilityCollector,
                               start_date: Optional[datetime] = None,
                               end_date: Optional[datetime] = None) -> int:
        """
        从指定数据源采集数据
        
        Args:
            source: 数据源名称
            collector: 采集器实例
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            采集的漏洞数量
        """
        try:
            logger.info(f"Collecting vulnerabilities from {source}")
            
            # 获取漏洞数据
            vulns = await collector.fetch_data(start_date, end_date)
            count = len(vulns)
            
            # 保存到数据库
            for vuln in vulns:
                self.db.add_vulnerability(vuln)
                
            logger.info(f"Collected {count} vulnerabilities from {source}")
            return count
            
        except Exception as e:
            logger.error(f"Failed to collect from {source}: {str(e)}")
            return 0
    
    async def collect_all(self,
                       start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None,
                       sources: Optional[List[str]] = None) -> Dict[str, int]:
        """
        从所有数据源采集数据
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            sources: 指定的数据源列表，默认为所有数据源
            
        Returns:
            各数据源采集的漏洞数量
        """
        if sources is None:
            sources = list(self.collectors.keys())
            
        # 创建采集任务
        tasks = []
        for source in sources:
            if source in self.collectors:
                task = self.collect_from_source(
                    source,
                    self.collectors[source],
                    start_date,
                    end_date
                )
                tasks.append(task)
            else:
                logger.warning(f"Unknown source: {source}")
        
        # 并行执行采集任务
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 统计结果
        stats = {}
        for source, result in zip(sources, results):
            if isinstance(result, Exception):
                logger.error(f"Collection failed for {source}: {str(result)}")
                stats[source] = 0
            else:
                stats[source] = result
        
        return stats
    
    def run_incremental(self,
                      days: int = 7,
                      sources: Optional[List[str]] = None) -> Dict[str, int]:
        """
        运行增量更新
        
        Args:
            days: 更新最近几天的数据
            sources: 指定的数据源列表
            
        Returns:
            各数据源采集的漏洞数量
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # 运行异步采集任务
        loop = asyncio.get_event_loop()
        stats = loop.run_until_complete(
            self.collect_all(start_date, end_date, sources)
        )
        
        return stats
    
    def run_full(self,
               start_date: Optional[datetime] = None,
               end_date: Optional[datetime] = None,
               sources: Optional[List[str]] = None) -> Dict[str, int]:
        """
        运行完整更新
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            sources: 指定的数据源列表
            
        Returns:
            各数据源采集的漏洞数量
        """
        # 运行异步采集任务
        loop = asyncio.get_event_loop()
        stats = loop.run_until_complete(
            self.collect_all(start_date, end_date, sources)
        )
        
        return stats

"""
使用示例：

1. 基本用法:
from services.collector import CollectorService

# 创建采集服务实例
service = CollectorService()

# 运行增量更新（最近7天的数据）
stats = service.run_incremental()
print(f"Collected vulnerabilities: {stats}")

2. 完整更新:
from datetime import datetime

# 指定日期范围
start_date = datetime(2024, 1, 1)
end_date = datetime(2024, 1, 31)

# 运行完整更新
stats = service.run_full(start_date, end_date)

3. 指定数据源:
# 只从NVD和GitHub采集数据
stats = service.run_incremental(sources=['nvd', 'github'])

4. 配置文件示例 (config/sources.json):
{
    "nvd": {
        "api_key": "your-nvd-api-key",
        "delay_between_requests": 6,
        "max_retries": 3,
        "timeout": 30
    },
    "github": {
        "api_key": "your-github-token",
        "delay_between_requests": 1,
        "max_retries": 3,
        "timeout": 30
    },
    "redhat": {
        "delay_between_requests": 1,
        "max_retries": 3,
        "timeout": 30
    },
    "debian": {
        "releases": ["buster", "bullseye", "bookworm"],
        "delay_between_requests": 1,
        "max_retries": 3,
        "timeout": 30
    }
}
""" 