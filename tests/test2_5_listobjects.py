#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import pyp11
    
print('Работа с функцией pyp11listobjects')

#lib = '/usr/local/lib64/librtpkcs11ecp_2.0.so'
lib = '/usr/local/lib64/libls11sw2016.so'
aa = pyp11.loadmodule(lib)
print (aa)
try:
    bb = pyp11.login (aa, 0, '01234567')
except:
    print('Except login: ')
    e = sys.exc_info()[1]
    e1 = e.args[0]
    print (e1)
    quit()

print (bb)
if bb != 1:
    quit()
tobj = 'объект'
type = 'all'
#type = 'cert'
#type = 'pubkey'
#type = 'data'
#type = 'privkey'
if (type == 'cert'):
    tobj = 'сертификат'
#Читаем объекты с токена
lm = pyp11.listobjects(aa, 0, type, 'value')
print('Работа с listobjects: ' + type)
i =0
for obj in lm:
    print (str(i) + '-ый ' + tobj)
    for key in obj.keys():
        print ('\t' + key + ': ' + obj[key])
    i += 1
#lm = pyp11.listobjects(aa, 0, 'cert', 'value')
#print('Работа с listobjects cert value:')
lm = pyp11.listobjects(aa, 0, 'pubkey', 'value')
print('Работа с listobjects pubkey value:')
i =0
for obj in lm:
    print (str(i) + '-ый объект')
    for key in obj.keys():
        print ('\t' + key + ': ' + obj[key])
    i += 1
bb = pyp11.logout (aa, 0)
