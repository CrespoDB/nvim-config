from setuptools import setup

setup(
    name="defanger",
    version="0.2",
    py_modules=["defanger"],
    install_requires=[
        "tldextract",
    ],
    entry_points={
        "console_scripts": [
            "defanger=defanger:main",
        ],
    },
)

