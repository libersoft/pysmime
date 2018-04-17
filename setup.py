from setuptools import setup

with open('requirements.txt') as f:
    install_requirements = f.readlines()

with open('test-requirements.txt') as f:
    test_requirements = f.readlines()

with open('README.md') as file:
    long_description = file.read()

setup(
    name='pysmime3',
    version='0.2.1',
    author='Lorenzo Gaggini',
    author_email='lg@lgaggini.net',
    packages=['pysmime'],
    url='http://libersoft.github.com/pysmime',
    license='LICENSE',
    keywords=['smime', 'openssl', 'm2crypto'],
    description='High level library for S/MIME basic functions',
    long_description=long_description,
    classifiers=[
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security :: Cryptography',
    ],
    install_requires=install_requirements,
    tests_require=test_requirements,
)
