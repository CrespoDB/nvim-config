from setuptools import setup, find_packages

setup(
    name="defanger",
    version="0.5",
    packages=find_packages(),
    install_requires=[
        "tldextract",
        "aiohttp",
    ],
    entry_points={
        "console_scripts": [
            "defanger=defanger.defanger:main",
            "enricher=defanger.enricher:main",
        ],
    },
)

