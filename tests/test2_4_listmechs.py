#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import pyp11

print('Работа с функциями:')
#print('load lib: ', pyp11.loadmodule('/usr/local/lib64/libls11sw2016_BLLi.so'))
#Выбираем библиотеку
#Программный токен
lib = '/usr/local/lib64/libls11sw2016.so'
#Для Windows
#lib='C:\Temp\ls11sw2016.dll'
#Облачный токен
#lib = '/usr/local/lib64/libls11cloud.so'
#Аппаратный токен
#lib = '/usr/local/lib64/librtpkcs11ecp_2.0.so'

try:
    aa = pyp11.loadmodule(lib, 2)
    print('load lib: ', aa)
except:
    print('Except load lib: ')
    e = sys.exc_info()[1]
    e1 = e.args[0]
    print (e1)

aa = pyp11.loadmodule(lib)
print (aa)
pyp11.unloadmodule(aa)
aa = pyp11.loadmodule(lib)
print (aa)
lm = pyp11.listmechs(aa, 0)
for v in lm:
    print (v)
