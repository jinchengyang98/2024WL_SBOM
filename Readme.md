# 开源软件供应链漏洞分析系统

一个基于Neo4j图数据库的开源软件供应链漏洞分析系统，专注于漏洞数据的采集、分析和传播路径追踪。

## 系统架构

### 1. 核心模块
```
src/
├── collectors/          # 漏洞数据采集器
├── models/             # 数据模型定义
├── services/           # 核心业务服务
└── utils/             # 通用工具类
```

### 2. 主要功能

#### 2.1 多源漏洞数据采集
- **支持数据源**
  - NVD (National Vulnerability Database)
  - GitHub Security Advisory
  - RedHat Security Data
  - Debian Security Tracker
- **采集特性**
  - 统一的采集器接口(BaseVulnerabilityCollector)
  - 增量式数据更新策略

#### 2.2 图数据库存储
- **数据模型**
  - 节点类型：Vulnerability、Component、Version、Patch
  - 关系类型：AFFECTS、HAS_VERSION、FIXED_BY、DEPENDS_ON
- **存储特性**
  - 高效的图查询能力
  - 批量数据处理支持

#### 2.3 漏洞分析能力
- **影响分析**
  - 直接和间接影响组件识别
  - 受影响版本统计
- **路径分析**
  - 多层级依赖追踪
  - 传播路径识别


## 环境要求

- Python 3.8+
- Neo4j 4.4+
- Git

## 快速开始

### 1. 环境准备
```bash
# 克隆代码库
git clone [repository-url]
cd [repository-name]

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 安装依赖
pip install -r requirements.txt

# 开发环境额外依赖
pip install -r requirements-dev.txt
```

### 2. 配置文件
1. 数据源配置
```bash
cp config/sources.json.example config/sources.json
```

编辑 `sources.json`:
```json
{
    "nvd": {
        "api_key": "your-api-key",
        "delay_between_requests": 6,
        "max_retries": 3
    },
    "github": {
        "token": "your-github-token",
        "delay_between_requests": 1
    }
}
```

2. 数据库配置
```bash
cp config/database.json.example config/database.json
```

编辑 `database.json`:
```json
{
    "uri": "bolt://localhost:7687",
    "username": "neo4j",
    "password": "your-password"
}
```

### 3. 基本使用

#### 数据采集
```bash
# 采集所有数据源
python -m src.services.collector

# 采集指定数据源
python -m src.services.collector --sources nvd github

# 指定时间范围采集
python -m src.services.collector --start-date 2024-01-01
```

#### 漏洞分析
```bash
# 分析漏洞影响范围
python -m src.services.analyzer --vuln-id CVE-2024-1234

# 分析组件依赖关系
python -m src.services.analyzer --component-name example-package
```

## 常见问题

### 1. API访问限制
- **问题**: 请求频繁被拒绝
- **解决**: 调整配置文件中的`delay_between_requests`参数
- **建议值**: NVD建议6秒，GitHub建议1秒

### 2. 内存使用优化
- **问题**: 处理大量数据时内存占用高
- **解决**: 使用批处理模式
- **示例**: 添加`--batch-size 1000`参数

### 3. 数据库连接
- **问题**: 无法连接Neo4j
- **解决**:
  1. 检查Neo4j服务是否运行
  2. 验证连接配置是否正确
  3. 确认防火墙设置

## 开发状态

### 已实现功能
- [x] 多源数据采集框架
- [x] 图数据库存储方案
- [x] 基础漏洞分析能力
- [x] 路径分析服务

### 开发中功能
- [ ] 文本分析与组件关联

