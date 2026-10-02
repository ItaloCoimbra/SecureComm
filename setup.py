#!/usr/bin/env python3
# setup.py

from pathlib import Path

from setuptools import setup, find_packages

ROOT = Path(__file__).resolve().parent

# Ler requisitos do arquivo requirements.txt
requirements = [
    line.split("#", 1)[0].strip()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if line.split("#", 1)[0].strip()
]

# Ler o README para a descrição longa
long_description = (ROOT / "README.md").read_text(encoding="utf-8")

# Isolated experiments remain optional; the messaging entrypoints do not import ML.
legacy_requirements = [
    "scikit-learn>=1.2.0", "pandas>=2.0.0", "numpy>=1.22.0", "joblib>=1.2.0",
    "pyreadline3>=3.4.1; sys_platform == 'win32'",
]

setup(
    name="securecomm",
    version="1.0.0",
    description="Chat E2EE experimental com vínculos locais e relays opacos",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    packages=find_packages(include=["client", "core", "server", "utils", "benchmark", "data"]),
    py_modules=["train_model"],
    include_package_data=False,
    package_data={"server": ["web_static/*", "web_static/assets/*"]},
    install_requires=requirements,
    extras_require={
        "dev": ["pytest>=7.0.0", "build>=1.2.2", "setuptools==80.9.0", "wheel==0.45.1"] + legacy_requirements,
        "legacy": legacy_requirements,
        "training": legacy_requirements + ["matplotlib>=3.7.0", "scipy>=1.10.0"],
    },
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications",
    ],
    entry_points={
        'console_scripts': [
            'securecomm-client=client.client:main',
            'securecomm-server=server.server:main',
            'securecomm-web=server.web_server:main',
        ],
    },
)
