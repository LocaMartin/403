from setuptools import setup, find_packages

setup(
    name="403",
    version="1.0.0",
    author="LocaMartin",
    author_email="locaboyff@gmail.com",
    description="403 Forbidden Bypass Tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/LocaMartin/403",
    packages=find_packages(),
    install_requires=[
        "requests",
        "colorama",
        "urllib3"
    ],
    entry_points={
        "console_scripts": [
            "403 = bypass403:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console"
    ],
    python_requires=">=3.6",
    keywords="security penetration-testing bug-bounty 403 bypass",
)