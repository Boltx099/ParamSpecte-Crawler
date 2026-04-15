from setuptools import setup

setup(
    name="paramspecter",
    version="1.0",
    description="Advanced Recon Crawler for Bug Bounty and Security Research",
    author="Boltx",
    py_modules=["ParamSpecter"],  # your file name without .py
    install_requires=[
        "requests",
        "beautifulsoup4",
    ],
    entry_points={
        "console_scripts": [
            "paramspecter=ParamSpecter:main",
        ],
    },
    python_requires=">=3.8",
)
