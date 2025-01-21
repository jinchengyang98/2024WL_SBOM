#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
数据库模型模块

定义了用于数据持久化存储的数据库模型。
使用SQLAlchemy ORM。
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, 
    Float, Boolean, ForeignKey, Table, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

Base = declarative_base()

# 多对多关系表
vulnerability_package = Table(
    'vulnerability_package', Base.metadata,
    Column('vulnerability_id', Integer, ForeignKey('vulnerabilities.id')),
    Column('package_id', Integer, ForeignKey('packages.id'))
)

vulnerability_reference = Table(
    'vulnerability_reference', Base.metadata,
    Column('vulnerability_id', Integer, ForeignKey('vulnerabilities.id')),
    Column('reference_id', Integer, ForeignKey('references.id'))
)

class DBVulnerability(Base):
    """漏洞数据库模型"""
    __tablename__ = 'vulnerabilities'
    
    # 基本信息
    id = Column(Integer, primary_key=True)
    vuln_id = Column(String(50), unique=True, nullable=False)  # CVE ID等
    source = Column(String(50), nullable=False)
    title = Column(String(500))
    description = Column(String(5000))
    
    # 时间信息
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    discovered_date = Column(DateTime)
    
    # 严重程度
    severity = Column(String(50))
    cvss_v3 = Column(JSON)
    cvss_v2 = Column(JSON)
    
    # 状态信息
    status = Column(String(50))
    scope = Column(String(500))
    
    # 关联信息
    affected_packages = relationship(
        'DBPackage',
        secondary=vulnerability_package,
        back_populates='vulnerabilities'
    )
    references = relationship(
        'DBReference',
        secondary=vulnerability_reference,
        back_populates='vulnerabilities'
    )
    
    # 其他信息
    patches = Column(JSON)
    notes = Column(JSON)
    raw_data = Column(JSON)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'id': self.vuln_id,
            'source': self.source,
            'title': self.title,
            'description': self.description,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'discovered_date': self.discovered_date.isoformat() if self.discovered_date else None,
            'severity': self.severity,
            'cvss_v3': self.cvss_v3,
            'cvss_v2': self.cvss_v2,
            'status': self.status,
            'scope': self.scope,
            'affected_packages': [pkg.to_dict() for pkg in self.affected_packages],
            'references': [ref.to_dict() for ref in self.references],
            'patches': self.patches,
            'notes': self.notes
        }

class DBPackage(Base):
    """软件包数据库模型"""
    __tablename__ = 'packages'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    ecosystem = Column(String(50))
    platform = Column(String(50))
    
    # 版本信息
    versions = Column(JSON)
    affected_versions = Column(JSON)
    fixed_versions = Column(JSON)
    
    # 关联信息
    vulnerabilities = relationship(
        'DBVulnerability',
        secondary=vulnerability_package,
        back_populates='affected_packages'
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'name': self.name,
            'ecosystem': self.ecosystem,
            'platform': self.platform,
            'versions': self.versions,
            'affected_versions': self.affected_versions,
            'fixed_versions': self.fixed_versions
        }

class DBReference(Base):
    """参考链接数据库模型"""
    __tablename__ = 'references'
    
    id = Column(Integer, primary_key=True)
    url = Column(String(500), nullable=False)
    source = Column(String(100))
    type = Column(String(50))
    tags = Column(JSON)
    
    # 关联信息
    vulnerabilities = relationship(
        'DBVulnerability',
        secondary=vulnerability_reference,
        back_populates='references'
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'url': self.url,
            'source': self.source,
            'type': self.type,
            'tags': self.tags
        }

class Database:
    """数据库管理类"""
    
    def __init__(self, url: str):
        """
        初始化数据库连接
        
        Args:
            url: 数据库连接URL
        """
        self.engine = create_engine(url)
        self.Session = sessionmaker(bind=self.engine)
        
    def create_tables(self):
        """创建所有表"""
        Base.metadata.create_all(self.engine)
        
    def drop_tables(self):
        """删除所有表"""
        Base.metadata.drop_all(self.engine)
        
    def add_vulnerability(self, vuln: 'Vulnerability') -> None:
        """
        添加漏洞数据
        
        Args:
            vuln: 漏洞实例
        """
        session = self.Session()
        try:
            # 检查是否已存在
            existing = session.query(DBVulnerability).filter_by(vuln_id=vuln.id).first()
            if existing:
                return self.update_vulnerability(vuln)
            
            # 创建数据库记录
            db_vuln = DBVulnerability(
                vuln_id=vuln.id,
                source=vuln.source,
                title=vuln.title,
                description=vuln.description,
                published_date=vuln.published_date,
                last_modified_date=vuln.last_modified_date,
                discovered_date=vuln.discovered_date,
                severity=vuln.severity,
                cvss_v3=vars(vuln.cvss_v3) if vuln.cvss_v3 else None,
                cvss_v2=vars(vuln.cvss_v2) if vuln.cvss_v2 else None,
                status=vuln.status,
                scope=vuln.scope,
                patches=vuln.patches,
                notes=vuln.notes,
                raw_data=vuln.raw_data
            )
            
            # 添加受影响的包
            for pkg in vuln.affected_packages:
                db_pkg = session.query(DBPackage).filter_by(name=pkg.name).first()
                if not db_pkg:
                    db_pkg = DBPackage(
                        name=pkg.name,
                        ecosystem=pkg.ecosystem,
                        platform=pkg.platform,
                        versions=[vars(v) for v in pkg.versions],
                        affected_versions=pkg.affected_versions,
                        fixed_versions=pkg.fixed_versions
                    )
                db_vuln.affected_packages.append(db_pkg)
            
            # 添加参考链接
            for ref in vuln.references:
                db_ref = session.query(DBReference).filter_by(url=ref.url).first()
                if not db_ref:
                    db_ref = DBReference(
                        url=ref.url,
                        source=ref.source,
                        type=ref.type,
                        tags=ref.tags
                    )
                db_vuln.references.append(db_ref)
            
            session.add(db_vuln)
            session.commit()
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
            
    def update_vulnerability(self, vuln: 'Vulnerability') -> None:
        """
        更新漏洞数据
        
        Args:
            vuln: 漏洞实例
        """
        session = self.Session()
        try:
            db_vuln = session.query(DBVulnerability).filter_by(vuln_id=vuln.id).first()
            if not db_vuln:
                return self.add_vulnerability(vuln)
            
            # 更新基本信息
            db_vuln.title = vuln.title
            db_vuln.description = vuln.description
            db_vuln.published_date = vuln.published_date
            db_vuln.last_modified_date = vuln.last_modified_date
            db_vuln.discovered_date = vuln.discovered_date
            db_vuln.severity = vuln.severity
            db_vuln.cvss_v3 = vars(vuln.cvss_v3) if vuln.cvss_v3 else None
            db_vuln.cvss_v2 = vars(vuln.cvss_v2) if vuln.cvss_v2 else None
            db_vuln.status = vuln.status
            db_vuln.scope = vuln.scope
            db_vuln.patches = vuln.patches
            db_vuln.notes = vuln.notes
            db_vuln.raw_data = vuln.raw_data
            
            # 更新受影响的包
            db_vuln.affected_packages = []
            for pkg in vuln.affected_packages:
                db_pkg = session.query(DBPackage).filter_by(name=pkg.name).first()
                if not db_pkg:
                    db_pkg = DBPackage(
                        name=pkg.name,
                        ecosystem=pkg.ecosystem,
                        platform=pkg.platform,
                        versions=[vars(v) for v in pkg.versions],
                        affected_versions=pkg.affected_versions,
                        fixed_versions=pkg.fixed_versions
                    )
                db_vuln.affected_packages.append(db_pkg)
            
            # 更新参考链接
            db_vuln.references = []
            for ref in vuln.references:
                db_ref = session.query(DBReference).filter_by(url=ref.url).first()
                if not db_ref:
                    db_ref = DBReference(
                        url=ref.url,
                        source=ref.source,
                        type=ref.type,
                        tags=ref.tags
                    )
                db_vuln.references.append(db_ref)
            
            session.commit()
            
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
            
    def get_vulnerability(self, vuln_id: str) -> Optional['Vulnerability']:
        """
        获取漏洞数据
        
        Args:
            vuln_id: 漏洞ID
            
        Returns:
            漏洞实例，如果不存在则返回None
        """
        session = self.Session()
        try:
            db_vuln = session.query(DBVulnerability).filter_by(vuln_id=vuln_id).first()
            if not db_vuln:
                return None
                
            return Vulnerability.from_dict(db_vuln.to_dict())
            
        finally:
            session.close()
            
    def get_vulnerabilities(self, 
                          source: Optional[str] = None,
                          start_date: Optional[datetime] = None,
                          end_date: Optional[datetime] = None) -> List['Vulnerability']:
        """
        获取漏洞数据列表
        
        Args:
            source: 数据源
            start_date: 开始日期
            end_date: 结束日期
            
        Returns:
            漏洞实例列表
        """
        session = self.Session()
        try:
            query = session.query(DBVulnerability)
            
            if source:
                query = query.filter_by(source=source)
            if start_date:
                query = query.filter(DBVulnerability.published_date >= start_date)
            if end_date:
                query = query.filter(DBVulnerability.published_date <= end_date)
                
            return [Vulnerability.from_dict(v.to_dict()) for v in query.all()]
            
        finally:
            session.close()
            
    def get_affected_packages(self, package_name: str) -> List['Vulnerability']:
        """
        获取影响指定包的漏洞列表
        
        Args:
            package_name: 包名
            
        Returns:
            漏洞实例列表
        """
        session = self.Session()
        try:
            db_pkg = session.query(DBPackage).filter_by(name=package_name).first()
            if not db_pkg:
                return []
                
            return [Vulnerability.from_dict(v.to_dict()) for v in db_pkg.vulnerabilities]
            
        finally:
            session.close() 