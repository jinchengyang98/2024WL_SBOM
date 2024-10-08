from dataclasses import dataclass, field
from typing import List, Dict, Union

@dataclass
class NVDData:
    cve_id: str
    description: str
    published_date: str
    last_modified_date: str
    cvss_v3_vector: str
    cvss_v3_base_score: float
    cwe_id: str
    references: List[Dict[str, Union[str, List[str]]]] = field(default_factory=list)
    configurations: List[Dict] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict) -> 'NVDData':
        cve_item = data.get('cve', {})
        
        # 处理描述
        description = next((desc.get('value', '') for desc in cve_item.get('descriptions', []) if desc.get('lang') == 'en'), '')
        
        # 处理 CVSS v3 信息
        metrics = cve_item.get('metrics', {}).get('cvssMetricV31', [{}])[0]
        cvss_data = metrics.get('cvssData', {})
        
        # 处理 CWE
        weaknesses = cve_item.get('weaknesses', [])
        cwe_id = next((desc.get('value', '').split(':')[0].strip() 
                       for weakness in weaknesses 
                       for desc in weakness.get('description', []) 
                       if desc.get('lang') == 'en' and desc.get('value', '').startswith('CWE-')), None)

        # 处理参考链接
        references = [
            {'url': ref.get('url', ''), 'source': ref.get('source', ''), 'tags': ref.get('tags', [])}
            for ref in cve_item.get('references', [])
        ]

        # 这一行代码创建并返回一个新的 NVDData 类实例，使用从输入的 JSON 数据中提取的各种属性值
        return cls(
            cve_id=cve_item.get('id', ''),  # 获取 CVE ID，如果不存在则返回空字符串
            description=description,  # 使用之前处理好的描述
            published_date=cve_item.get('published', ''),  # 获取发布日期，如果不存在则返回空字符串
            last_modified_date=cve_item.get('lastModified', ''),  # 获取最后修改日期，如果不存在则返回空字符串
            cvss_v3_vector=cvss_data.get('vectorString', ''),  # 获取 CVSS v3 向量字符串，如果不存在则返回空字符串
            cvss_v3_base_score=cvss_data.get('baseScore', 0.0),  # 获取 CVSS v3 基础分数，如果不存在则返回 0.0
            cwe_id=cwe_id,  # 使用之前处理好的 CWE ID
            references=references,  # 使用之前处理好的参考链接列表
            configurations=cve_item.get('configurations', [])  # 获取配置信息，如果不存在则返回空列表
        )