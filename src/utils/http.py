#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
HTTP请求工具模块

提供统一的HTTP请求处理功能，支持：
1. 同步/异步请求
2. 自动重试
3. 请求限速
4. 代理支持
5. 会话管理
6. 响应缓存
"""

import time
import json
import asyncio
from typing import Dict, Any, Optional, Union
from datetime import datetime, timedelta
import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from cachetools import TTLCache

from .logger import logger

class RateLimiter:
    """请求限速器"""
    
    def __init__(self, calls: int, period: float):
        """
        初始化限速器
        
        Args:
            calls: 允许的请求次数
            period: 时间周期(秒)
        """
        self.calls = calls
        self.period = period
        self.timestamps = []
        
    async def acquire(self):
        """获取请求许可"""
        now = datetime.now()
        
        # 清理过期的时间戳
        self.timestamps = [ts for ts in self.timestamps 
                         if now - ts < timedelta(seconds=self.period)]
        
        # 检查是否超过限制
        if len(self.timestamps) >= self.calls:
            # 计算需要等待的时间
            wait_time = (self.timestamps[0] + timedelta(seconds=self.period) - now).total_seconds()
            if wait_time > 0:
                logger.debug(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                await asyncio.sleep(wait_time)
        
        # 添加新的时间戳
        self.timestamps.append(now)

class HTTPClient:
    """HTTP客户端"""
    
    def __init__(self,
                base_url: str = "",
                headers: Optional[Dict[str, str]] = None,
                timeout: int = 30,
                max_retries: int = 3,
                backoff_factor: float = 0.3,
                rate_limit_calls: Optional[int] = None,
                rate_limit_period: Optional[float] = None,
                proxy: Optional[str] = None,
                verify_ssl: bool = True,
                cache_ttl: Optional[int] = None):
        """
        初始化HTTP客户端
        
        Args:
            base_url: 基础URL
            headers: 请求头
            timeout: 超时时间(秒)
            max_retries: 最大重试次数
            backoff_factor: 重试延迟因子
            rate_limit_calls: 速率限制的请求次数
            rate_limit_period: 速率限制的时间周期(秒)
            proxy: 代理服务器
            verify_ssl: 是否验证SSL证书
            cache_ttl: 缓存过期时间(秒)
        """
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        
        # 配置重试策略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        
        # 创建会话
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # 配置限速器
        self.rate_limiter = None
        if rate_limit_calls and rate_limit_period:
            self.rate_limiter = RateLimiter(rate_limit_calls, rate_limit_period)
        
        # 配置缓存
        self.cache = None
        if cache_ttl:
            self.cache = TTLCache(maxsize=100, ttl=cache_ttl)
    
    def _build_url(self, endpoint: str) -> str:
        """构建完整的URL"""
        if self.base_url and not endpoint.startswith(('http://', 'https://')):
            return f"{self.base_url}/{endpoint.lstrip('/')}"
        return endpoint
    
    def _get_cache_key(self, method: str, url: str, **kwargs) -> str:
        """生成缓存键"""
        cache_dict = {
            'method': method,
            'url': url,
            'params': kwargs.get('params'),
            'data': kwargs.get('data'),
            'json': kwargs.get('json')
        }
        return json.dumps(cache_dict, sort_keys=True)
    
    async def _wait_for_rate_limit(self):
        """等待速率限制"""
        if self.rate_limiter:
            await self.rate_limiter.acquire()
    
    def request(self,
               method: str,
               endpoint: str,
               **kwargs) -> requests.Response:
        """
        发送同步HTTP请求
        
        Args:
            method: 请求方法
            endpoint: 请求端点
            **kwargs: 其他请求参数
            
        Returns:
            响应对象
        """
        url = self._build_url(endpoint)
        
        # 检查缓存
        if self.cache and method.upper() == 'GET':
            cache_key = self._get_cache_key(method, url, **kwargs)
            if cache_key in self.cache:
                logger.debug(f"Cache hit for {url}")
                return self.cache[cache_key]
        
        # 合并请求头
        headers = {**self.headers, **kwargs.pop('headers', {})}
        
        # 设置代理
        if self.proxy:
            kwargs['proxies'] = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        # 发送请求
        try:
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            response.raise_for_status()
            
            # 缓存响应
            if self.cache and method.upper() == 'GET':
                self.cache[cache_key] = response
            
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise
    
    async def arequest(self,
                     method: str,
                     endpoint: str,
                     **kwargs) -> aiohttp.ClientResponse:
        """
        发送异步HTTP请求
        
        Args:
            method: 请求方法
            endpoint: 请求端点
            **kwargs: 其他请求参数
            
        Returns:
            响应对象
        """
        url = self._build_url(endpoint)
        
        # 等待速率限制
        await self._wait_for_rate_limit()
        
        # 检查缓存
        if self.cache and method.upper() == 'GET':
            cache_key = self._get_cache_key(method, url, **kwargs)
            if cache_key in self.cache:
                logger.debug(f"Cache hit for {url}")
                return self.cache[cache_key]
        
        # 合并请求头
        headers = {**self.headers, **kwargs.pop('headers', {})}
        
        # 创建客户端会话
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.request(
                    method,
                    url,
                    ssl=self.verify_ssl,
                    proxy=self.proxy,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    **kwargs
                ) as response:
                    await response.read()
                    response.raise_for_status()
                    
                    # 缓存响应
                    if self.cache and method.upper() == 'GET':
                        self.cache[cache_key] = response
                    
                    return response
                    
            except aiohttp.ClientError as e:
                logger.error(f"Async request failed: {str(e)}")
                raise
    
    def get(self, endpoint: str, **kwargs) -> requests.Response:
        """发送GET请求"""
        return self.request('GET', endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs) -> requests.Response:
        """发送POST请求"""
        return self.request('POST', endpoint, **kwargs)
    
    def put(self, endpoint: str, **kwargs) -> requests.Response:
        """发送PUT请求"""
        return self.request('PUT', endpoint, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> requests.Response:
        """发送DELETE请求"""
        return self.request('DELETE', endpoint, **kwargs)
    
    async def aget(self, endpoint: str, **kwargs) -> aiohttp.ClientResponse:
        """发送异步GET请求"""
        return await self.arequest('GET', endpoint, **kwargs)
    
    async def apost(self, endpoint: str, **kwargs) -> aiohttp.ClientResponse:
        """发送异步POST请求"""
        return await self.arequest('POST', endpoint, **kwargs)
    
    async def aput(self, endpoint: str, **kwargs) -> aiohttp.ClientResponse:
        """发送异步PUT请求"""
        return await self.arequest('PUT', endpoint, **kwargs)
    
    async def adelete(self, endpoint: str, **kwargs) -> aiohttp.ClientResponse:
        """发送异步DELETE请求"""
        return await self.arequest('DELETE', endpoint, **kwargs)

"""
使用示例：

1. 基本用法:
from utils.http import HTTPClient

client = HTTPClient(
    base_url="https://api.example.com",
    headers={"Authorization": "Bearer token"}
)

# 同步请求
response = client.get("/users")
data = response.json()

# 异步请求
async def fetch_data():
    response = await client.aget("/users")
    data = await response.json()

2. 带缓存的请求:
client = HTTPClient(
    base_url="https://api.example.com",
    cache_ttl=300  # 缓存5分钟
)

# 第一次请求会访问API
response1 = client.get("/data")
# 第二次请求会使用缓存
response2 = client.get("/data")

3. 带速率限制的请求:
client = HTTPClient(
    base_url="https://api.example.com",
    rate_limit_calls=100,
    rate_limit_period=60  # 每分钟最多100次请求
)

async def bulk_fetch():
    for i in range(200):
        response = await client.aget(f"/items/{i}")
        # 自动处理速率限制
""" 