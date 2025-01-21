#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
日志配置工具模块

提供统一的日志记录功能，支持：
1. 控制台输出
2. 文件记录
3. 日志分级
4. 日志轮转
5. 自定义格式
"""

import os
import sys
from datetime import datetime
from typing import Optional
from loguru import logger

# 默认的日志格式
DEFAULT_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
    "<level>{message}</level>"
)

class Logger:
    """日志管理类"""
    
    def __init__(self, 
                log_dir: str = "logs",
                console_level: str = "INFO",
                file_level: str = "DEBUG",
                retention: str = "30 days",
                rotation: str = "100 MB",
                format: str = DEFAULT_FORMAT):
        """
        初始化日志配置
        
        Args:
            log_dir: 日志文件目录
            console_level: 控制台日志级别
            file_level: 文件日志级别
            retention: 日志保留时间
            rotation: 日志文件大小限制
            format: 日志格式
        """
        self.log_dir = log_dir
        self.console_level = console_level
        self.file_level = file_level
        self.retention = retention
        self.rotation = rotation
        self.format = format
        
        # 创建日志目录
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # 配置日志记录器
        self._configure_logger()
        
    def _configure_logger(self):
        """配置日志记录器"""
        # 移除默认处理器
        logger.remove()
        
        # 添加控制台处理器
        logger.add(
            sys.stderr,
            format=self.format,
            level=self.console_level,
            colorize=True
        )
        
        # 添加文件处理器
        logger.add(
            os.path.join(self.log_dir, "{time:YYYY-MM-DD}.log"),
            format=self.format,
            level=self.file_level,
            rotation=self.rotation,
            retention=self.retention,
            encoding="utf-8"
        )
        
        # 添加错误日志处理器
        logger.add(
            os.path.join(self.log_dir, "error_{time:YYYY-MM-DD}.log"),
            format=self.format,
            level="ERROR",
            rotation=self.rotation,
            retention=self.retention,
            encoding="utf-8",
            filter=lambda record: record["level"].name == "ERROR"
        )
        
    def get_logger(self, name: Optional[str] = None):
        """
        获取日志记录器
        
        Args:
            name: 日志记录器名称，默认为None
            
        Returns:
            日志记录器实例
        """
        if name:
            return logger.bind(name=name)
        return logger
    
    @staticmethod
    def set_level(level: str):
        """
        设置全局日志级别
        
        Args:
            level: 日志级别
        """
        logger.level(level)
        
    @staticmethod
    def disable(name: str):
        """
        禁用指定模块的日志
        
        Args:
            name: 模块名称
        """
        logger.disable(name)
        
    @staticmethod
    def enable(name: str):
        """
        启用指定模块的日志
        
        Args:
            name: 模块名称
        """
        logger.enable(name)

# 创建默认日志记录器实例
default_logger = Logger()
logger = default_logger.get_logger()

# 导出常用的日志记录函数
debug = logger.debug
info = logger.info
warning = logger.warning
error = logger.error
critical = logger.critical

"""
使用示例：

1. 使用默认日志记录器:
from utils.logger import logger, info, error

info("这是一条信息日志")
error("这是一条错误日志")

2. 创建自定义日志记录器:
from utils.logger import Logger

custom_logger = Logger(
    log_dir="custom_logs",
    console_level="DEBUG",
    file_level="INFO"
)
logger = custom_logger.get_logger("custom")

logger.info("这是一条自定义日志")

3. 禁用/启用特定模块的日志:
from utils.logger import Logger

Logger.disable("noisy_module")
Logger.enable("noisy_module")
""" 