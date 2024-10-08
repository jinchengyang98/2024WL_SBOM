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

### 1. 环境准备

1. 确保已安装 Python 3.7 或更高版本。
2. 安装所需的 Python 库:
   ```bash
   pip install -r requirements.txt
   ```
3. 安装并启动 Neo4j 数据库。

### 2. 配置

1. 在 `程序/source/config/` 目录下创建 `config.py` 文件，添加以下内容:
   ```python
   ROOT_PATH = "你的项目根目录路径"
   DATA_PATH = "data"
   NVD_DATA_PATH = ROOT_PATH + "\\" + DATA_PATH + "\\" + "CVE\\NVD"
   MAX_FILES_TO_PROCESS = 10  # 可以根据需要调整这个值
   ```
2. 在 `程序/source/config/config_nvd_github.json` 文件中配置 NVD API 参数。

### 3. 数据收集

```
python source/1_vulnerability_data_collector.py
```

这将从 NVD 数据源获取漏洞数据，并将其保存为 JSON 文件，按年份和 CVE ID 组织。

### 4. 数据清洗和存储

运行数据清洗和存储脚本:

```
python source/2_vulnerability_data_cleaner.py
```
这将解析收集到的 NVD 数据，提取关键信息，创建实体，并将数据存储到 Neo4j 图数据库中。

### 5. 执行查询

目前，基础查询功能已经实现，但尚未提供独立的查询脚本。您可以通过 Neo4j 的 Cypher 查询语言直接在 Neo4j 浏览器中执行查询，例如：

1. 查找特定 CVE 影响的组件和版本:
   ```cypher
   MATCH (v:Vulnerability {cve_id: 'CVE-2021-44228'})-[:AFFECTS]->(c:Component)-[:HAS_VERSION]->(ver:Version)
   RETURN v.cve_id, c.product, ver.version
   ```

2. 查找特定组件的漏洞历史:
   ```cypher
   MATCH (c:Component {product: 'log4j'})<-[:AFFECTS]-(v:Vulnerability)
   RETURN v.cve_id, v.published_date, v.cvss_v3_base_score
   ORDER BY v.published_date DESC
   ```

3. 识别可能的补丁信息:
   ```cypher
   MATCH (p:Patch)-[:FIXES]->(v:Vulnerability {cve_id: 'CVE-2021-44228'})
   RETURN p.patch_id, p.patch_url
   ```

### 6. 查看结果

查询结果将在 Neo4j 浏览器中显示。对于更复杂的查询和可视化，请参考 Neo4j 文档或等待后续的可视化功能实现。

## 注意事项

- 请确保在运行脚本之前已正确配置所有必要的设置。
- 数据收集过程可能需要一些时间，具体取决于您设置的数据量和网络条件。
- 在进行大规模数据处理时，请注意监控系统资源使用情况。