import json
from neo4j import GraphDatabase
from .entities import Vulnerability, Component, Version, Patch
import logging

class Neo4jConnector:
    """Neo4j数据库连接器类"""
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        """关闭数据库连接"""
        self.driver.close()

    def create_vulnerability(self, vulnerability: Vulnerability):
        """创建漏洞节点"""
        with self.driver.session() as session:
            session.write_transaction(self._create_vulnerability_node, vulnerability)

    @staticmethod
    def _create_vulnerability_node(tx, vulnerability: Vulnerability):
        """创建漏洞节点的具体实现"""
        query = """
        MERGE (v:Vulnerability {cve_id: $cve_id})
        SET v.description = $description,
            v.published_date = $published_date,
            v.last_modified_date = $last_modified_date,
            v.cvss_v3_vector = $cvss_v3_vector,
            v.cvss_v3_base_score = $cvss_v3_base_score,
            v.cwe_id = $cwe_id,
            v.references = $references
        """
        try:
            tx.run(query, 
                   cve_id=vulnerability.cve_id, 
                   description=vulnerability.description,
                   published_date=vulnerability.published_date,
                   last_modified_date=vulnerability.last_modified_date,
                   cvss_v3_vector=vulnerability.cvss_v3_vector,
                   cvss_v3_base_score=vulnerability.cvss_v3_base_score,
                   cwe_id=vulnerability.cwe_id,
                   references=json.dumps(vulnerability.references))  # 将references序列化为JSON字符串
            logging.debug(f"Created vulnerability node: {vulnerability.cve_id}")
        except Exception as e:
            logging.error(f"Error creating vulnerability node: {e}", exc_info=True)
            raise
        
    def create_component(self, component: Component):
        """创建组件节点"""
        with self.driver.session() as session:
            session.write_transaction(self._create_component_node, component)

    @staticmethod
    def _create_component_node(tx, component: Component):
        """创建组件节点的具体实现"""
        query = """
        MERGE (c:Component {cpe23Uri: $cpe23Uri})
        SET c.vendor = $vendor, c.product = $product
        """
        tx.run(query, cpe23Uri=component.cpe23Uri, vendor=component.vendor, product=component.product)
        logging.debug(f"Created component node: {component.cpe23Uri}")

    def create_version(self, version: Version):
        """创建版本节点"""
        with self.driver.session() as session:
            session.write_transaction(self._create_version_node, version)

    @staticmethod
    def _create_version_node(tx, version: Version):
        """创建版本节点的具体实现"""
        query = """
        MERGE (v:Version {cpe23Uri: $cpe23Uri})
        SET v.version = $version,
            v.version_start_including = $version_start_including,
            v.version_start_excluding = $version_start_excluding,
            v.version_end_including = $version_end_including,
            v.version_end_excluding = $version_end_excluding
        WITH v
        MATCH (c:Component {cpe23Uri: $cpe23Uri})
        MERGE (c)-[:HAS_VERSION]->(v)
        """
        tx.run(query, 
               cpe23Uri=version.cpe23Uri,
               version=version.version,
               version_start_including=version.version_start_including,
               version_start_excluding=version.version_start_excluding,
               version_end_including=version.version_end_including,
               version_end_excluding=version.version_end_excluding)

    def create_patch(self, patch: Patch):
        """创建补丁节点"""
        with self.driver.session() as session:
            session.write_transaction(self._create_patch_node, patch)

    @staticmethod
    def _create_patch_node(tx, patch: Patch):
        """创建补丁节点的具体实现"""
        query = (
            "MERGE (p:Patch {id: $patch_id}) "
            "SET p.url = $patch_url"
        )
        tx.run(query, patch_id=patch.patch_id, patch_url=patch.patch_url)

    def create_relationship(self, from_node, to_node, relationship_type, properties=None):
        """创建节点之间的关系"""
        with self.driver.session() as session:
            session.write_transaction(self._create_relationship, from_node, to_node, relationship_type, properties)

    @staticmethod
    def _create_relationship(tx, from_node, to_node, relationship_type, properties):
        """创建节点之间关系的具体实现"""
        query = (
            f"MATCH (a), (b) "
            f"WHERE a.{from_node['key']} = ${from_node['key']} AND b.{to_node['key']} = ${to_node['key']} "
            f"MERGE (a)-[r:{relationship_type}]->(b) "
        )
        if properties:
            query += "SET " + ", ".join(f"r.{k} = ${k}" for k in properties.keys())
        
        params = {from_node['key']: from_node['value'], to_node['key']: to_node['value']}
        if properties:
            params.update(properties)
        
        tx.run(query, **params)