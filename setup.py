from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='paseto',
    version='0.0.5',
    description='Platform-Agnostic Security Tokens for Python (PASETO)',
    long_description=long_description,
    license='MIT',
    url='https://github.com/rlittlefield/pypaseto',
    author='J. Ryan Littlefield',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='past security stateless tokens',
    py_modules=["paseto"],
    install_requires=['pysodium', 'pendulum'],
    data_files=[("", ["LICENSE"])],
)
