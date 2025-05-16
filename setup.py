#!/usr/bin/env python3
# setup.py

from setuptools import setup, find_packages
import os

# Ler requisitos do arquivo requirements.txt
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f if not line.startswith('#') and line.strip()]

# Ler o README para a descrição longa
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="securecomm",
    version="1.0.0",
    description="Sistema de Comunicação Segura com Chaves Dinâmicas e Detecção de Intrusão via ML",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Seu Nome",
    author_email="seu.email@exemplo.com",
    packages=find_packages(),
    install_requires=requirements,
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications",
    ],
    entry_points={
        'console_scripts': [
            'securecomm-client=client.client:main',
            'securecomm-server=server.server:main',
        ],
    },
) 