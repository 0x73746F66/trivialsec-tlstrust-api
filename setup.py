from setuptools import setup

setup(
    name="tlstrust-api",
    version="0.0.7",
    author='Christopher Langton',
    author_email='chris@trivialsec.com',
    description="Utilities that assist with trust relationship checking of X.509 Certificates for various end-user devices with disparate root trust stores.",
    long_description="""
    """,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/trivialsec/tlstrust-api",
    project_urls={
        "Source": "https://gitlab.com/trivialsec/tlstrust-api",
        "Documentation": "https://gitlab.com/trivialsec/tlstrust-api/-/blob/main/README.md",
        "Tracker": "https://gitlab.com/trivialsec/tlstrust-api/-/issues",
    },
    classifiers=[
        "Operating System :: OS Independent",
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    include_package_data=True,
    install_requires=[
        'fastapi==0.75.1',
        'tlstrust==2.6.1',
        'validators==0.18.2',
        'uvicorn[standard]'
    ],
    python_requires=">=3.9",
    options={"bdist_wheel": {"universal": "1"}},
)
