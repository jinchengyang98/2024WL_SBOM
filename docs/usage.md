# 漏洞数据分析系统使用说明

## 1. 系统功能

本系统提供以下主要功能：
- 多源漏洞数据采集
- 漏洞数据清洗
- 漏洞数据分析
- 数据导出

## 2. 使用前准备

### 2.1 环境配置

1. 确保已安装Python 3.8+
2. 安装依赖包：
```bash
pip install -r requirements.txt
```

### 2.2 配置数据源

1. 在`config/sources.json`中配置数据源信息：

```json
{
    "sources": {
        "NVD": {
            "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "api_key": "your-nvd-api-key",
            "delay_between_requests": 6,
            "max_retries": 3,
            "timeout": 30
        },
        "GitHub": {
            "api_token": "your-github-token",
            "delay_between_requests": 3,
            "max_retries": 3,
            "timeout": 30,
            "per_page": 100
        }
    }
}
```

2. 获取必要的API密钥：
- NVD API密钥：访问 https://nvd.nist.gov/developers/request-an-api-key
- GitHub Token：访问 https://github.com/settings/tokens

## 3. 使用说明

### 3.1 数据采集

#### 3.1.1 采集所有数据源
```bash
python -m src.services.collector
```

#### 3.1.2 采集指定数据源
```bash
python -m src.services.collector --sources NVD GitHub
```

#### 3.1.3 指定时间范围采集
```bash
python -m src.services.collector --start-date 2024-01-01 --end-date 2024-03-01
```

### 3.2 数据清洗

```bash
python -m src.services.cleaner
```

### 3.3 数据分析

#### 3.3.1 漏洞关联分析
```bash
python -m src.services.analyzer --type correlation
```

#### 3.3.2 漏洞趋势分析
```bash
python -m src.services.analyzer --type trend
```

### 3.4 数据导出

```bash
python -m src.services.exporter --format json --output ./output
```

## 4. 日志查看

- 应用日志：`logs/app.log`
- 错误日志：`logs/error.log`

## 5. 常见问题

### 5.1 API限流

问题：请求频率过高导致API限流
解决：调整配置文件中的`delay_between_requests`参数

### 5.2 数据源连接超时

问题：网络不稳定导致连接超时
解决：
1. 检查网络连接
2. 增加`timeout`参数值
3. 增加`max_retries`参数值

### 5.3 内存占用过高

问题：处理大量数据时内存占用过高
解决：使用`--batch-size`参数控制批处理大小

## 6. 注意事项

1. 请遵守各数据源的使用条款和API限制
2. 定期备份重要数据
3. 及时更新API密钥
4. 监控系统日志，及时处理异常

## 7. 联系方式

如有问题，请通过以下方式联系：
- 提交Issue：[GitHub Issues](https://github.com/your-repo/issues)
- 邮件：your-email@example.com 