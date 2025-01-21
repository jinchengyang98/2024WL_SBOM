# 漏洞数据分析系统API文档

## 1. 数据采集器API

### 1.1 基础采集器接口

#### BaseVulnerabilityCollector

基础漏洞数据采集器类，所有具体的数据源采集器都需要继承此类。

```python
class BaseVulnerabilityCollector:
    """基础漏洞数据采集器。
    
    提供统一的数据采集接口和基础功能实现。
    """
    
    def __init__(self, config: Dict[str, Any]):
        """初始化采集器。
        
        Args:
            config: 配置信息字典
        """
        pass
        
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """获取指定时间范围内的漏洞数据。
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            包含漏洞信息的字典列表
            
        Raises:
            NotImplementedError: 子类必须实现此方法
        """
        raise NotImplementedError
```

### 1.2 NVD采集器

#### NVDCollector

用于采集NVD（国家漏洞数据库）的漏洞数据。

```python
class NVDCollector(BaseVulnerabilityCollector):
    """NVD漏洞数据采集器。"""
    
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """获取NVD漏洞数据。
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            包含NVD漏洞信息的字典列表
            
        Raises:
            RequestError: API请求失败时
            ValidationError: 数据验证失败时
        """
        pass
```

### 1.3 GitHub采集器

#### GitHubCollector

用于采集GitHub安全公告数据。

```python
class GitHubCollector(BaseVulnerabilityCollector):
    """GitHub漏洞数据采集器。"""
    
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """获取GitHub安全公告数据。
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            包含GitHub安全公告信息的字典列表
            
        Raises:
            RequestError: API请求失败时
            ValidationError: 数据验证失败时
        """
        pass
```

### 1.4 RedHat采集器

#### RedHatCollector

用于采集RedHat安全公告数据。

```python
class RedHatCollector(BaseVulnerabilityCollector):
    """RedHat漏洞数据采集器。"""
    
    def fetch_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """获取RedHat安全公告数据。
        
        Args:
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            包含RedHat安全公告信息的字典列表
            
        Raises:
            RequestError: API请求失败时
            ValidationError: 数据验证失败时
        """
        pass
```

## 2. 数据模型API

### 2.1 基础漏洞模型

#### VulnerabilityData

基础漏洞数据模型。

```python
class VulnerabilityData:
    """漏洞数据基础模型。"""
    
    def __init__(self, data: Dict[str, Any]):
        """初始化漏洞数据。
        
        Args:
            data: 原始漏洞数据字典
        """
        pass
        
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式。
        
        Returns:
            包含漏洞信息的字典
        """
        pass
        
    def validate(self) -> bool:
        """验证数据有效性。
        
        Returns:
            数据是否有效
        """
        pass
```

### 2.2 NVD数据模型

#### NVDData

NVD漏洞数据模型。

```python
class NVDData(VulnerabilityData):
    """NVD漏洞数据模型。"""
    
    def __init__(self, data: Dict[str, Any]):
        """初始化NVD漏洞数据。
        
        Args:
            data: 原始NVD数据字典
        """
        super().__init__(data)
```

## 3. 数据清洗API

### 3.1 基础清洗器

#### BaseDataCleaner

基础数据清洗器接口。

```python
class BaseDataCleaner:
    """基础数据清洗器。"""
    
    def clean(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """清洗数据。
        
        Args:
            data: 原始数据列表
            
        Returns:
            清洗后的数据列表
        """
        pass
```

### 3.2 标准化清洗器

#### StandardizationCleaner

数据标准化清洗器。

```python
class StandardizationCleaner(BaseDataCleaner):
    """数据标准化清洗器。"""
    
    def clean(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """标准化数据格式。
        
        Args:
            data: 原始数据列表
            
        Returns:
            标准化后的数据列表
        """
        pass
```

## 4. 数据分析API

### 4.1 关联分析器

#### CorrelationAnalyzer

漏洞关联分析器。

```python
class CorrelationAnalyzer:
    """漏洞关联分析器。"""
    
    def analyze(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析漏洞之间的关联关系。
        
        Args:
            data: 漏洞数据列表
            
        Returns:
            关联分析结果
        """
        pass
```

### 4.2 趋势分析器

#### TrendAnalyzer

漏洞趋势分析器。

```python
class TrendAnalyzer:
    """漏洞趋势分析器。"""
    
    def analyze(self, data: List[Dict[str, Any]], 
                time_range: str = "monthly") -> Dict[str, Any]:
        """分析漏洞趋势。
        
        Args:
            data: 漏洞数据列表
            time_range: 时间范围，可选值："daily"、"weekly"、"monthly"、"yearly"
            
        Returns:
            趋势分析结果
        """
        pass
```

## 5. 工具函数API

### 5.1 HTTP请求

```python
def make_request(url: str, 
                method: str = "GET", 
                params: Dict[str, Any] = None,
                headers: Dict[str, str] = None,
                timeout: int = 30,
                max_retries: int = 3) -> requests.Response:
    """发送HTTP请求。
    
    Args:
        url: 请求URL
        method: 请求方法
        params: 请求参数
        headers: 请求头
        timeout: 超时时间（秒）
        max_retries: 最大重试次数
        
    Returns:
        请求响应对象
        
    Raises:
        RequestError: 请求失败时
    """
    pass
```

### 5.2 数据验证

```python
def validate_date_range(start_date: datetime, end_date: datetime) -> bool:
    """验证日期范围有效性。
    
    Args:
        start_date: 开始日期
        end_date: 结束日期
        
    Returns:
        日期范围是否有效
        
    Raises:
        ValueError: 日期范围无效时
    """
    pass
```

## 6. 异常类

### 6.1 请求异常

```python
class RequestError(Exception):
    """HTTP请求异常。"""
    pass
```

### 6.2 验证异常

```python
class ValidationError(Exception):
    """数据验证异常。"""
    pass
```

## 7. 配置项

### 7.1 数据源配置

```json
{
    "sources": {
        "NVD": {
            "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "api_key": "your-api-key",
            "delay_between_requests": 6,
            "max_retries": 3,
            "timeout": 30
        }
    }
}
```

### 7.2 日志配置

```json
{
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO"
        }
    }
}
```

## 8. 返回值格式

### 8.1 漏洞数据格式

```json
{
    "id": "CVE-2024-1234",
    "description": "漏洞描述",
    "published_date": "2024-01-01T00:00:00Z",
    "last_modified_date": "2024-01-02T00:00:00Z",
    "severity": "HIGH",
    "cvss_score": 8.5,
    "references": [
        {
            "url": "https://example.com/advisory",
            "source": "ADVISORY"
        }
    ]
}
```

### 8.2 分析结果格式

```json
{
    "correlation": {
        "related_vulnerabilities": [
            {
                "source": "CVE-2024-1234",
                "target": "CVE-2024-5678",
                "relationship": "SIMILAR"
            }
        ]
    },
    "trend": {
        "monthly": [
            {
                "date": "2024-01",
                "count": 123,
                "severity_distribution": {
                    "HIGH": 45,
                    "MEDIUM": 56,
                    "LOW": 22
                }
            }
        ]
    }
}
``` 