#!/usr/bin/python3
#-*- coding: utf-8 -*-

from distutils.core import setup, Extension

mdl = Extension('pyp11', sources = ['src/pythonpkcs11.c', 'src/gost_r3411_2012.c'])

classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: GNU General Public License (GPL)",
    "Natural Language :: Russian",
    "Operating System :: Linux ",
    "Operating System :: OS X ",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: OS Independent",
    "Operating System :: Unix",
    "Programming Language :: C",
    "Programming Language :: Python",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Libraries :: Python Modules",
]
description = """A PKCS#11 with GOST wrapper for Python"""

setup(name = 'pyp11',
    version = '1.0.0',
    description = 'A PKCS#11 with GOST wrapper for Python',
    keywords="crypto,pki,pkcs11,c,gost",
    classifiers=classifiers,
    platforms="Win32 Unix OS X",
    long_description=description,
    author="Vladimir Orlov",
    author_email="vorlov@lissi.ru",
    ext_modules = [mdl],
    py_modules=['Token'])