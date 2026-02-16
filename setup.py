from setuptools import setup, find_packages

setup(
    name="security-test-xapp",
    version="1.0.0",
    description="O-RAN Near-RT RIC Security Compliance Testing xApp",
    author="Your Organization",
    author_email="security@example.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "ricxappframe>=3.2.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "PyJWT>=2.8.0",
        "pyyaml>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "security-xapp=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.10",
)