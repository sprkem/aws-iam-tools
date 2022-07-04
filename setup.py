from setuptools import setup, find_packages

setup(
    name='AWS IAM Tools',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'Click==8.0.1',
        'boto3==1.24.19',
        'PTable==0.9.2'
    ],
    entry_points={
        'console_scripts': [
            'ait = src.cli:cli',
        ],
    },
)