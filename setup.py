#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
from setuptools import setup, find_packages

# 读取版本号
def get_version():
    init = open(os.path.join("src", "__init__.py"), "r", encoding="utf-8").read()
    return re.search(r"^__version__ = ['\"]([^'\"]+)['\"]", init, re.M).group(1)

# 读取README文件
def get_long_description():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# 读取requirements.txt
def get_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="vulnerability-analysis",
    version=get_version(),
    author="Your Name",
    author_email="your.email@example.com",
    description="一个多源漏洞数据采集和分析系统",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/vulnerability-analysis",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=get_requirements(),
    extras_require={
        "dev": [
            line.strip()
            for line in open("requirements-dev.txt", encoding="utf-8")
            if line.strip() and not line.startswith(("#", "-r"))
        ]
    },
    entry_points={
        "console_scripts": [
            "vuln-collector=src.services.collector:main",
            "vuln-cleaner=src.services.cleaner:main",
            "vuln-analyzer=src.services.analyzer:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.json", "*.yaml", "*.yml"],
    },
    zip_safe=False,
    project_urls={
        "Bug Reports": "https://github.com/your-repo/vulnerability-analysis/issues",
        "Source": "https://github.com/your-repo/vulnerability-analysis",
        "Documentation": "https://vulnerability-analysis.readthedocs.io/",
    },
) 