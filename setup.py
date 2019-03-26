#!/usr/bin/env python

from distutils.core import setup

setup(
    name='genconfdrv',
    version='0.1.0',
    description='',
    author='Sebastian Lohff',
    author_email='seba@someserver.de',
    url='https://git.someserver.de/seba/genconfdrv/',
    python_requires='>=3.5',
    packages=['genconfdrv'],
    install_requires=['fs'],
    license='Apache License, Version 2.0',
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Environment :: Console',
    ],
    entry_points={
        'console_scripts': [
            'genconfdrv = genconfdrv.genconfdrv:main'
        ]
    },
)
