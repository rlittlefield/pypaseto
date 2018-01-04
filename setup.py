from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pypast',
    version='0.0.1',
    description='Platform-Agnostic Security Tokens for Python',
    long_description=long_description,
    url='https://github.com/JimDabell/pypast',
    author='Jim Dabell',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='past security stateless tokens',
	py_modules=["pypast"],
    install_requires=['libnacl>=1.6.1'],
)
