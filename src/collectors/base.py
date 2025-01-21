#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
基础漏洞数据采集器模块

提供了漏洞数据采集器的基础接口和通用功能实现。
所有具体的数据源采集器都需要继承这个基类。
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import time

from ..utils.http import make_request, handle_rate_limit
from ..utils.logger import setup_logger

logger = logging.getLogger(__name__)

class BaseVulnerabilityCollector(ABC):
    """
    漏洞数据采集器基类
    
    提供了基础的数据采集接口和通用功能实现。
    具体的数据源采集器需要继承此类并实现相应的方法。
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化采集器
        
        Args:
            config: 数据源配置信息，包含以下字段：
                - url: API地址
                - api_key: API密钥（可选）
                - delay_between_requests: 请求间隔时间（秒）
                - max_retries: 最大重试次数
                - timeout: 请求超时时间（秒）
        """
        self.config = config
        self.url = config.get('url', '')
        self.api_key = config.get('api_key', '')
        self.delay = config.get('delay_between_requests', 6)
        self.max_retries = config.get('max_retries', 3)
        self.timeout = config.get('timeout', 30)
        
        # 设置日志
        setup_logger()
        
    @abstractmethod
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """
        获取指定时间范围内的漏洞数据
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            包含漏洞信息的字典列表
            
        Raises:
            NotImplementedError: 子类必须实现此方法
        """
        raise NotImplementedError
    
    def make_api_request(self, 
                        endpoint: str, 
                        method: str = "GET", 
                        params: Optional[Dict[str, Any]] = None,
                        headers: Optional[Dict[str, str]] = None,
                        data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        发送API请求
        
        Args:
            endpoint: API端点
            method: 请求方法，默认为"GET"
            params: 查询参数
            headers: 请求头
            data: 请求体数据
            
        Returns:
            API响应数据
            
        Raises:
            RequestError: 请求失败时抛出
        """
        # 构建完整URL
        url = f"{self.url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # 添加通用请求头
        if headers is None:
            headers = {}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
            
        # 发送请求
        response = make_request(
            url=url,
            method=method,
            params=params,
            headers=headers,
            data=data,
            timeout=self.timeout,
            max_retries=self.max_retries
        )
        
        # 处理限流
        handle_rate_limit(response)
        
        # 请求间隔
        time.sleep(self.delay)
        
        return response.json()
    
    def validate_date_range(self, start_date: datetime, end_date: datetime) -> None:
        """
        验证日期范围的有效性
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Raises:
            ValueError: 日期范围无效时抛出
        """
        if not isinstance(start_date, datetime) or not isinstance(end_date, datetime):
            raise ValueError("开始日期和结束日期必须是datetime类型")
            
        if start_date > end_date:
            raise ValueError("开始日期不能晚于结束日期")
            
        if end_date > datetime.now():
            raise ValueError("结束日期不能晚于当前时间")
    
    def clean_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        清理和标准化原始数据
        
        Args:
            data: 原始数据
            
        Returns:
            清理后的数据
        """
        # 基础实现，子类可以重写此方法进行特定的数据清理
        return data
    
    def handle_error(self, error: Exception, context: str = "") -> None:
        """
        处理异常
        
        Args:
            error: 异常对象
            context: 错误上下文信息
        """
        error_msg = f"{context} - {str(error)}" if context else str(error)
        logger.error(error_msg)
        # 可以在这里添加更多的错误处理逻辑，比如通知、重试等 