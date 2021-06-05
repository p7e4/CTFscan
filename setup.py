#!/usr/bin/python3
import setuptools

with open("README.md") as f:
    description = f.read()

from ctfscan import __version__

setuptools.setup(
    name="CTFscan",
    version=__version__,
    author="p7e4",
    author_email="p7e4@qq.com",
    description="web dir scanner",
    long_description=description,
    long_description_content_type="text/markdown",
    url="https://github.com/p7e4/CTFscan",
    packages=setuptools.find_packages(),
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology"
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'ctfscan = ctfscan:main'
        ]
    }
)

