#!/usr/bin/python3

import sys
from Token import Token

import pyp11

def listslots (handle):
    slots = pyp11.listslots(aa)
    i = 0
    lslots = []
    for v in slots:
        for f in v[2]:
    	    if (f == 'TOKEN_PRESENT'):
#                print ('slotid=',v[0], '\n\tlabeltok=',v[1], '\n\tflags=',v[2], '\n\tinfotok=',v[3])
                i = 1
                lslots.append(v)
                break
    i += 1
    return (lslots)
    
print('Список токенов')
#Библиотеки для Linux
#Программный токен
lib = '/usr/local/lib64/libls11sw2016.so'
#Облачный токен
#lib = '/usr/local/lib64/libls11cloud.so'
#Аппаратный токен
#lib = '/usr/local/lib64/librtpkcs11ecp_2.0.so'
#Библиотеки для Windows
#lib='C:\Temp\ls11sw2016.dll'

try:
    aa = pyp11.loadmodule(lib)
    print('Handle библиотеки ' + lib + ': ' + aa)
except:
    print('Except load lib: ')
    e = sys.exc_info()[1]
    e1 = e.args[0]
    print (e1)
    quit()

#slots = pyp11.listslots(aa)
slots = listslots(aa)
i = 0
for v in slots:
    for f in v[2]:
        if (f == 'TOKEN_PRESENT'):
    	    if (i == 0):
    	        print ('\nИнформация о токенах в слотах\n')
    	    it = v[3]
    	    print ('slotid=' + str(v[0]))
    	    print ('\tFlags=' + str(v[2]))
    	    print ('\tLabel="' + it[0].strip() + '"')
    	    print ('\tManufacturer="' + it[1].strip() + '"')
    	    print ('\tModel="' + it[2].strip() + '"')
    	    print ('\tSerialNumber="' + it[3].strip() + '"')
    	    i = 1
    	    break
    i += 1
pyp11.unloadmodule(aa)

if (i == 0):
    print ('Нет ни одного подключенного токена. Вставьте токен и повторите операцию')
quit()
