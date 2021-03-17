#!/usr/bin/python3

import sys
import pyp11
from Token import Token

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
    aa = pyp11.loadmodule(lib)
    print('load lib: ', aa)
except:
    print('Except load lib: ')
    e = sys.exc_info()[1]
    e1 = e.args[0]
    print (e1)
    quit()

#Серийный номер токена
sn = '228CBB83AEC1EA19'
slot = 0
#Создаем объект токена
t1 = Token(aa, slot, sn)
if (t1.returncode != ''):
    print (t1.returncode)
#Уничтожение объекта
    del t1
    quit()

lm, stat = t1.listmechs()
if (stat != ''):
    print (stat)
    quit()
print ('Механизмы токена')
for v in lm:
    print (v)
del t1
quit()
