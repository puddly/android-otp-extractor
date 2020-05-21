import pathlib
from setuptools import setup, find_packages

setup(
    name='android-otp-extractor',
    version='1.0.2',
    description='Extracts and exports OTP secrets from most Android OTP apps',

    long_description=(pathlib.Path(__file__).parent / 'README.md').read_text(),
    long_description_content_type='text/markdown',

    url='https://github.com/puddly/android-otp-extractor',
    author='puddly',
    author_email='puddly3@gmail.com',

    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: System :: Archiving :: Backup',

        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],

    keywords='android otp secret exporting',

    package_dir={'': 'src'},
    packages=find_packages(where='src'),

    python_requires='>=3.6, <4',
    install_requires=['cryptography>=2.0', 'coloredlogs'],

    project_urls={
        'Bug Reports': 'https://github.com/puddly/android-otp-extractor/issues',
        'Source': 'https://github.com/puddly/android-otp-extractor/',
    },
)