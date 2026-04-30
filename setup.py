#!/usr/bin/env python3
"""
Setup for Yellow Sign - Secrets Scanner
"""

from setuptools import setup, find_packages
import os

# Read README
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()
else:
    long_description = "Yellow Sign - A powerful secrets detection tool"

setup(
    name="yellow-sign",
    version="1.0.0",
    author="rhizor",
    author_email="rhizor@example.com",
    description="A powerful secrets detection tool for scanning code and configurations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rhizor/yellow-sign",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "yellow-sign=yellow_sign.cli:cli",
        ],
    },
    keywords="security secrets scanning detection credentials",
    project_urls={
        "Bug Reports": "https://github.com/rhizor/yellow-sign/issues",
        "Source": "https://github.com/rhizor/yellow-sign",
    },
)
