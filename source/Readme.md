# 漏洞数据分析系统

## 系统实体关系

本系统包含以下主要实体及其关系：

1. Vulnerability（漏洞）
   - 属性：cve_id, published_date, description, CPEs, CWE, CVSS2
   - 关系：
     - AFFECT -> Software
     - AFFECT_VERSION -> Version
     - FIX -> Software

2. Software（组件）
   - 属性：name, author, url
   - 关系：
     - HAS -> Version
     - REUSE -> Version
     - REUSE -> Software

3. Version（版本）
   - 属性：tag, version, commit_date, repo_name, author
   - 关系：
     - REUSE -> Version

4. Patch（补丁）
   - 属性：fix_cve_id, commit_id, repo_owner, repo_name, commit_date
   - 关系：
     - FIX_CVE -> Vulnerability
     - FIX_VERSION -> Version

## 已实现功能

1. 数据收集
   - 从 NVD 数据源获取漏洞数据
   - 将获取的数据保存为 JSON 文件，按年份和 CVE ID 组织

2. 数据清洗和存储
   - 解析 NVD JSON 数据，提取关键信息
   - 创建 Vulnerability、Component、Version 和 Patch 实体
   - 将实体数据存储到 Neo4j 图数据库中
   - 建立实体之间的关系（如 AFFECTS, HAS_VERSION, FIXES 等）

3. 基础查询功能
   - 查找特定 CVE 影响的组件和版本
   - 查找特定组件的漏洞历史
   - 识别可能的补丁信息

## 待实现功能

1. 高级关联分析
   - 实现软件依赖关系的分析
   - 分析漏洞在不同项目间的传播路径

2. 可视化
   - 开发图形界面，展示漏洞、软件、版本之间的关系
   - 提供交互式查询和分析工具

3. 报告生成
   - 自动生成漏洞影响报告和风险评估报告

4. 实时更新
   - 实现数据源的实时监控和更新机制

5. API 接口
   - 开发 RESTful API，允许其他系统集成和查询数据

## 使用说明

[在这里添加系统的基本使用说明，包括如何运行数据收集、数据清洗和存储脚本，以及如何执行基本的查询操作]

## 依赖

- Python 3.7+
- Neo4j 数据库
- requests 库
- neo4j-driver 库

## 安装和配置

[在这里添加如何安装必要的依赖，以及如何配置系统的说明]

