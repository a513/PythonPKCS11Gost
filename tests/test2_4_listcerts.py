#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import time
import pyp11
    
print('Список сертификатов токена')

aa = pyp11.loadmodule('/usr/local/lib64/libls11sw2016.so')
#aa = pyp11.loadmodule('/usr/local/lib64/librtpkcs11ecp_2.0.so')
print (aa)
lcerts = pyp11.listcerts(aa, 0)
if (len(lcerts) == 0):
    print ('На токене нет сертификатов')
    quit()
#Перебираем сертификаты
i = 0
for cert in lcerts:
    print (str(i) + '-ый сертификат')
    #Информация о сертификате
    for key in cert:
        print ('\t' + key + ': ' + cert[key])
    i += 1
#Сравним с pyp11.listobjects
tobj = 'объект'
#type = 'all'
#type = 'cert'
#type = 'pubkey'
#type = 'data'
type = 'privkey'
if (type == 'cert'):
    tobj = 'сертификат'
print('Работа с listobjects:')
#lm = pyp11.listobjects(aa, 0, type, 'value')
pyp11.login(aa, 0, '01234567')
lm = pyp11.listobjects(aa, 0, type)
i = 0
for obj in lm:
    print (str(i) + '-ый ' + tobj)
    for key in obj:
        print ('\t' + key + ': ' + obj[key])
    i += 1
quit()