from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

try:
    # Get the long description from the README file
    with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
        long_description = f.read()
except Exception as e:
    long_description = "Ausdigital connectivity library"

setup(
    name='python-ausdigital',
    version='0.0.1',
    description='Ausdigital connectivity library',
    long_description=long_description,
    url='https://github.com/tradewire/ausdigital-client',
    author='Ausdigital.org team',
    author_email='hi@ausdigital.org',
    license='BSD',

    classifiers=[
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        # of course we support python2, but it hasn't been tested completely yet
        # 'Programming Language :: Python :: 2',
        # 'Programming Language :: Python :: 2.7',
        # 'Programming Language :: Python :: 3',
        # 'Programming Language :: Python :: 3.3',
        # 'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='ausdigital.org',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=['requests', 'gnupg', 'python-dateutil'],
)
