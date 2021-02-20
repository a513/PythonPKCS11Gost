#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import time

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
try:
    aa = pyp11.loadmodule('/usr/local/lib64/libls11sw2016.so', 2)
    print('load lib: ', aa)
except:
    print('Except load lib: ')
    e = sys.exc_info()[1]
    e1 = e.args[0]
    print (e1)

aa = pyp11.loadmodule('/usr/local/lib64/libls11sw2016.so')
pyp11.unloadmodule(aa)
aa = pyp11.loadmodule('/usr/local/lib64/libls11sw2016.so')
#aa = pyp11.loadmodule('/usr/local/lib64/librtpkcs11ecp_2.0.so')
print (aa)


#slots = pyp11.listslots(aa)
slots = listslots(aa)
i = 0
for v in slots:
    for f in v[2]:
        if (f == 'TOKEN_PRESENT'):
            print ('slotid=' + str(v[0]))
            print ('\tlabeltok=\"' + v[1] + '\"\n\tflags=' + str(v[2]) + '\n\tinfotok=' + str(v[3]))
            i = 1
            break
    i += 1
pyp11.unloadmodule(aa)

if (i == 0):
    print ('Нет ни одного подключенного токена. Вставьте токен и повторите операцию')
quit()
