from model.logger_config import logger as logging   
from typing import List

class Vulnerability:
    """漏洞类，用于存储漏洞相关信息"""
    def __init__(self, cve_id, description, published_date, last_modified_date, 
                 cvss_v3_vector, cvss_v3_base_score, cwe_id, references):
        self.cve_id = cve_id
        self.description = description
        self.published_date = published_date
        self.last_modified_date = last_modified_date
        self.cvss_v3_vector = cvss_v3_vector
        self.cvss_v3_base_score = cvss_v3_base_score
        self.cwe_id = cwe_id
        self.references = references  # 这里保持为列表

class Component:
    """组件类，用于存储受影响组件的信息"""
    def __init__(self, cpe23Uri, vendor, product):
        self.cpe23Uri = cpe23Uri
        self.vendor = vendor
        self.product = product
    
    @staticmethod
    def process_component(nvd_obj,neo4j_connector):
            # 3. 处理受影响的组件和版本
            cve_id = nvd_obj.cve_id
            configurations = nvd_obj.configurations
            for config_wrapper in configurations:
                if isinstance(config_wrapper, dict) and 'nodes' in config_wrapper:
                    nodes = config_wrapper['nodes']
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        if not cpe_matches and 'children' in node:
                            for child in node.get('children', []):
                                cpe_matches.extend(child.get('cpeMatch', []))

                        for cpe_match in cpe_matches:
                            if cpe_match.get('vulnerable', True):  # 只处理易受攻击的组件
                                cpe23Uri = cpe_match.get('criteria')
                                if cpe23Uri:
                                    parts = cpe23Uri.split(':')
                                    if len(parts) > 5:
                                        vendor = parts[3]
                                        product = parts[4]
                                        version_str = parts[5]
                                        
                                        # 处理版本为 '*' 的情况
                                        if version_str == '*':
                                            version_str = "All Versions"
                                        
                                        component = Component(cpe23Uri, vendor, product)
                                        version = Version(version_str, cpe23Uri, 
                                                          cpe_match.get('versionStartIncluding'),
                                                          cpe_match.get('versionStartExcluding'),
                                                          cpe_match.get('versionEndIncluding'),
                                                          cpe_match.get('versionEndExcluding'))
                                        
                                        logging.debug(f"Creating component: {component.cpe23Uri}")
                                        neo4j_connector.create_component(component)
                                        
                                        logging.debug(f"Creating version: {version.version} for {version.cpe23Uri}")
                                        neo4j_connector.create_version(version)
                                        
                                        logging.debug(f"Creating AFFECTS relationship: {cve_id} -> {cpe23Uri}")
                                        neo4j_connector.create_relationship(
                                            {'key': 'cve_id', 'value': cve_id},
                                            {'key': 'cpe23Uri', 'value': cpe23Uri},
                                            'AFFECTS'
                                        )

class Version:
    """版本类，用于存储受影响组件的版本信息"""
    def __init__(self, version, cpe23Uri, version_start_including=None, version_start_excluding=None,
                 version_end_including=None, version_end_excluding=None):
        self.version = version
        self.cpe23Uri = cpe23Uri
        self.version_start_including = version_start_including
        self.version_start_excluding = version_start_excluding
        self.version_end_including = version_end_including
        self.version_end_excluding = version_end_excluding

class Patch:
    """补丁类，用于存储补丁信息"""
    def __init__(self, patch_id, patch_url):
        self.patch_id = patch_id
        self.patch_url = patch_url
    
    @staticmethod
    def process_patch(nvd_obj,neo4j_connector):
        for ref in nvd_obj.references:
            url = ref.get('url', '')
            tags = ref.get('tags', [])
            if Patch.is_likely_patch(url, tags):
                patch_id = f"PATCH-{nvd_obj.cve_id}-{url}"
                patch = Patch(patch_id, url)
                logging.debug(f"Creating patch: {patch_id}")
                neo4j_connector.create_patch(patch)
                logging.debug(f"Creating FIXES relationship: {patch_id} -> {nvd_obj.cve_id}")


    @staticmethod
    def is_likely_patch(url: str, tags: List[str]) -> bool:
        """
        判断一个URL是否可能是补丁链接
        """
        # 定义可能表示补丁的关键词
        patch_keywords = ['patch', 'fix', 'update', 'resolve', 'mitigate']
        
        # 检查URL
        url_lower = url.lower()
        return any(keyword in url_lower for keyword in patch_keywords) or 'Patch' in tags
