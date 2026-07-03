from setuptools import setup, find_packages

setup(
    name="dart_sast",
    version="1.0.0",
    description="Static Application Security Testing (SAST) for Dart & Flutter.",
    long_description=open("README.md", encoding="utf-8").read() if open("README.md") else "",
    long_description_content_type="text/markdown",
    author="Scientific Artifact SBRC 2026",
    author_email="author@sbrc2026.org",
    url="https://github.com/doc-artefatos/dart_sast",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "dart_sast = dart_sast.main:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
