#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
文件操作工具模块

提供统一的文件处理功能，支持：
1. 文件读写
2. JSON/YAML处理
3. CSV处理
4. 文件压缩/解压
5. 文件监控
"""

import os
import json
import csv
import yaml
import gzip
import shutil
import tempfile
from typing import Dict, List, Any, Union, Optional, TextIO
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from .logger import logger

class FileHandler:
    """文件处理类"""
    
    @staticmethod
    def read_text(file_path: Union[str, Path], encoding: str = 'utf-8') -> str:
        """
        读取文本文件
        
        Args:
            file_path: 文件路径
            encoding: 文件编码
            
        Returns:
            文件内容
        """
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def write_text(file_path: Union[str, Path],
                  content: str,
                  encoding: str = 'utf-8',
                  append: bool = False) -> None:
        """
        写入文本文件
        
        Args:
            file_path: 文件路径
            content: 文件内容
            encoding: 文件编码
            append: 是否追加模式
        """
        mode = 'a' if append else 'w'
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, mode, encoding=encoding) as f:
                f.write(content)
        except Exception as e:
            logger.error(f"Failed to write file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def read_json(file_path: Union[str, Path], encoding: str = 'utf-8') -> Dict:
        """
        读取JSON文件
        
        Args:
            file_path: 文件路径
            encoding: 文件编码
            
        Returns:
            JSON数据
        """
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read JSON file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def write_json(file_path: Union[str, Path],
                  data: Dict,
                  encoding: str = 'utf-8',
                  indent: int = 4) -> None:
        """
        写入JSON文件
        
        Args:
            file_path: 文件路径
            data: JSON数据
            encoding: 文件编码
            indent: 缩进空格数
        """
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding=encoding) as f:
                json.dump(data, f, ensure_ascii=False, indent=indent)
        except Exception as e:
            logger.error(f"Failed to write JSON file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def read_yaml(file_path: Union[str, Path], encoding: str = 'utf-8') -> Dict:
        """
        读取YAML文件
        
        Args:
            file_path: 文件路径
            encoding: 文件编码
            
        Returns:
            YAML数据
        """
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to read YAML file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def write_yaml(file_path: Union[str, Path],
                  data: Dict,
                  encoding: str = 'utf-8') -> None:
        """
        写入YAML文件
        
        Args:
            file_path: 文件路径
            data: YAML数据
            encoding: 文件编码
        """
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding=encoding) as f:
                yaml.safe_dump(data, f, allow_unicode=True)
        except Exception as e:
            logger.error(f"Failed to write YAML file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def read_csv(file_path: Union[str, Path],
                encoding: str = 'utf-8',
                delimiter: str = ',',
                **kwargs) -> List[Dict]:
        """
        读取CSV文件
        
        Args:
            file_path: 文件路径
            encoding: 文件编码
            delimiter: 分隔符
            **kwargs: 其他CSV读取参数
            
        Returns:
            CSV数据列表
        """
        try:
            with open(file_path, 'r', encoding=encoding, newline='') as f:
                reader = csv.DictReader(f, delimiter=delimiter, **kwargs)
                return list(reader)
        except Exception as e:
            logger.error(f"Failed to read CSV file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def write_csv(file_path: Union[str, Path],
                 data: List[Dict],
                 fieldnames: Optional[List[str]] = None,
                 encoding: str = 'utf-8',
                 delimiter: str = ',',
                 **kwargs) -> None:
        """
        写入CSV文件
        
        Args:
            file_path: 文件路径
            data: CSV数据列表
            fieldnames: 字段名列表
            encoding: 文件编码
            delimiter: 分隔符
            **kwargs: 其他CSV写入参数
        """
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding=encoding, newline='') as f:
                if not fieldnames and data:
                    fieldnames = list(data[0].keys())
                writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delimiter, **kwargs)
                writer.writeheader()
                writer.writerows(data)
        except Exception as e:
            logger.error(f"Failed to write CSV file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def compress_file(file_path: Union[str, Path],
                    output_path: Optional[Union[str, Path]] = None) -> str:
        """
        压缩文件
        
        Args:
            file_path: 源文件路径
            output_path: 输出文件路径，默认为源文件路径加.gz后缀
            
        Returns:
            压缩后的文件路径
        """
        if output_path is None:
            output_path = str(file_path) + '.gz'
            
        try:
            with open(file_path, 'rb') as f_in:
                with gzip.open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return output_path
        except Exception as e:
            logger.error(f"Failed to compress file {file_path}: {str(e)}")
            raise
    
    @staticmethod
    def decompress_file(file_path: Union[str, Path],
                      output_path: Optional[Union[str, Path]] = None) -> str:
        """
        解压文件
        
        Args:
            file_path: 压缩文件路径
            output_path: 输出文件路径，默认为去掉.gz后缀的路径
            
        Returns:
            解压后的文件路径
        """
        if output_path is None:
            output_path = str(file_path).rstrip('.gz')
            
        try:
            with gzip.open(file_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return output_path
        except Exception as e:
            logger.error(f"Failed to decompress file {file_path}: {str(e)}")
            raise

class FileWatcher:
    """文件监控类"""
    
    def __init__(self, path: Union[str, Path], recursive: bool = False):
        """
        初始化文件监控器
        
        Args:
            path: 监控路径
            recursive: 是否递归监控子目录
        """
        self.path = path
        self.recursive = recursive
        self.observer = Observer()
        self.handlers = []
        
    def add_handler(self, handler: FileSystemEventHandler):
        """
        添加事件处理器
        
        Args:
            handler: 事件处理器
        """
        self.handlers.append(handler)
        self.observer.schedule(handler, self.path, recursive=self.recursive)
        
    def start(self):
        """启动监控"""
        self.observer.start()
        
    def stop(self):
        """停止监控"""
        self.observer.stop()
        self.observer.join()

class SafeFileHandler:
    """安全文件处理类"""
    
    @staticmethod
    def safe_write(file_path: Union[str, Path],
                  write_func: callable,
                  *args,
                  **kwargs) -> None:
        """
        安全写入文件
        
        首先写入临时文件，然后原子性地替换目标文件。
        这样可以避免写入过程中的文件损坏。
        
        Args:
            file_path: 目标文件路径
            write_func: 写入函数
            *args: 写入函数的位置参数
            **kwargs: 写入函数的关键字参数
        """
        # 创建临时文件
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(file_path),
            prefix=os.path.basename(file_path) + '.',
            suffix='.tmp'
        )
        os.close(temp_fd)
        
        try:
            # 写入临时文件
            write_func(temp_path, *args, **kwargs)
            
            # 在Windows上，需要先删除目标文件
            if os.name == 'nt' and os.path.exists(file_path):
                os.remove(file_path)
                
            # 原子性地替换文件
            os.rename(temp_path, file_path)
            
        except Exception:
            # 清理临时文件
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

"""
使用示例：

1. 基本文件操作:
from utils.file import FileHandler

# 读写文本文件
content = FileHandler.read_text('config.txt')
FileHandler.write_text('output.txt', 'Hello, World!')

# 读写JSON文件
data = FileHandler.read_json('config.json')
FileHandler.write_json('output.json', {'name': 'test'})

# 读写YAML文件
config = FileHandler.read_yaml('config.yaml')
FileHandler.write_yaml('output.yaml', {'env': 'prod'})

# 读写CSV文件
records = FileHandler.read_csv('data.csv')
FileHandler.write_csv('output.csv', [{'id': 1, 'name': 'test'}])

2. 文件压缩:
# 压缩文件
compressed_path = FileHandler.compress_file('large_file.txt')
# 解压文件
original_path = FileHandler.decompress_file('large_file.txt.gz')

3. 文件监控:
from utils.file import FileWatcher
from watchdog.events import FileSystemEventHandler

class MyHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            print(f"File {event.src_path} has been modified")

watcher = FileWatcher("monitored_directory")
watcher.add_handler(MyHandler())
watcher.start()

4. 安全文件写入:
from utils.file import SafeFileHandler, FileHandler

# 安全地写入JSON文件
SafeFileHandler.safe_write(
    'important.json',
    FileHandler.write_json,
    {'critical': 'data'}
)
""" 