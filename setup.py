from setuptools import setup, find_packages

setup(
    name="nihilist",
    version="1.0",
    url="https://github.com/casterbyte/Nihilist",
    author="Magama Bazarov",
    author_email="caster@exploit.org",
    scripts=['nihilist.py'],
    description="Cisco IOS Security Inspector",
    long_description=open('README.md', encoding="utf8").read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['network security', 'config analyzer', 'cisco', 'cisco ios', 'hardening', 'networks'],
    packages=find_packages(),
    install_requires=[
        'colorama',
        'netmiko',
    ],
    entry_points={
        "console_scripts": ["nihilist = nihilist:main"],
    },
    python_requires='>=3.11',
)