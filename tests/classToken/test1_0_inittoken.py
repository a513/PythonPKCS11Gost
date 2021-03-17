#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import pyp11
from Token import Token

print('Работа с функциями inittoken:')

#Выбираем библиотеку
#Программный токен
lib = '/usr/local/lib64/libls11sw2016.so'
#Для Windows
#lib='C:\Temp\ls11sw2016.dll'
#Облачный токен
#lib = '/usr/local/lib64/libls11cloud.so'
#Аппаратный токен
#lib = '/usr/local/lib64/librtpkcs11ecp_2.0.so'

#Загружаем библиотеку
libid = pyp11.loadmodule(lib)
#Дескриптор библиотеки
#print (libid)
#Загружаем список слотов
slots = pyp11.listslots(libid)
tokpr = 0
#Ищем первый подключенный токен
while (tokpr == 0):
#Перебираем слоты
    for v in slots:
        #Список флагов текущего слота
        flags = v[2]
#Проверяем наличие в стоке токена
        if (flags.count('TOKEN_PRESENT') !=0):
            tokpr = 1
#Избавляемся от лишних пробелов у метки слота
            lab = v[1].strip()
#Информация о токене
            infotok = v[3]
            slotid = v[0]
#Серийный номер токена
            sn = infotok[3]
            break
    if (tokpr == 0):
        input ('Нет ни одного подключенного токена.\nВставьте токен и нажмите ВВОД')
    slots = pyp11.listslots(libid)

#Для тестирования удаляем флаги  'TOKEN_INITIALIZED'
if (flags.count('TOKEN_INITIALIZED') != 0):
    flags.remove('TOKEN_INITIALIZED')

#Информация о подключенном токене
print ('Текущие флаги слота и токена в нем: ', flags)

#Проверяем, что токен проинициализирован
if (flags.count('TOKEN_INITIALIZED') == 0 or lab == ''):
    print ('\n\tТребуется проинициализировать токен\n')
    slot = 0
    t1 = Token(libid, slot, sn)
    if (t1.returncode != ''):
        print (t1.returncode)
#Уничтожение объекта
        del t1
        quit()
#    dd = pyp11.inittoken (libid, 0, '87654321',"TESTPY2")
    dd = t1.inittoken ('87654321',"TESTPY2")
    print ('Установлена метка токена TESTPY.')
    del t1

t1 = Token(libid, slot, sn)
if (t1.returncode != ''):
    print (t1.returncode)
#Уничтожение объекта
    del t1
    quit()
tinfo = t1.tokinfo()
for ll in tinfo:
    for key in ll:
        print (key + ': ' + ll[key])
print ('Флаги токена и слота: ' + str(t1.flags))
quit()
