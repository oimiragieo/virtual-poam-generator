"""
Setup script for KARP Clone - Nessus Report Processor
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "KARP Clone - Nessus Report Processor"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="virtual-poam-generator",
    version="1.0.0",
    author="Virtual POAM Generator Team",
    author_email="support@example.com",
    description="DoD eMASS compliance tool - Generates POAMs and reports from Nessus scans",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/virtual-poam-generator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "pdf": ["weasyprint>=60.0"],
        "dev": ["pytest>=7.0", "black>=22.0", "flake8>=5.0"],
    },
    entry_points={
        "console_scripts": [
            "poam-generator=cli:main",
            "virtual-poam=cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/*.html", "templates/templates/*.html"],
    },
)
