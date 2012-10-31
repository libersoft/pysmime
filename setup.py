from distutils.core import setup

with open('README.md') as file:
    long_description = file.read()

setup(
    name = 'pysmime',
    version = '0.1.0',
    author = 'Lorenzo Gaggini',
    author_email = 'lg@libersoft.it',
    packages = ['pysmime', 'pysmime.test'],
    url = 'http://libersoft.github.com/pysmime',
    license = 'LICENSE',
    keywords = ['smime', 'openssl', 'm2crypto'],
    description = 'High level library for S/MIME basic functions',
    long_description = long_description,
    classifiers = [
        'Programming Language :: Python',
        'Development Status :: 3 - Alpha',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security :: Cryptography',
        ],
    install_requires = [
        "M2Crypto == 0.21.1"
    ],
)
