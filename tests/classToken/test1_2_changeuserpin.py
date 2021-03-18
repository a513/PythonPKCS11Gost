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
            infotok = v[3]
            slotid = v[0]
            break
    if (tokpr == 0):
        input ('Нет ни одного подключенного токена.\nВставьте токен и нажмите ВВОД')
#Серийный номер токена
sn = infotok[3]
#Создаем объект токена
t1 = Token(libid, slotid, sn)
if (t1.returncode != ''):
    print (t1.returncode)
#Уничтожение объекта
    del t1
    quit()
#Проверяем, что заводской USER-PIN надо поменять 
if (t1.flags.count('USER_PIN_TO_BE_CHANGED') > 0 ):
    print ('Требуется сменить пользовательский (use) PIN-код')
#    pyp11.logout(libid, 0)
    dd2 = t1.changeuserpin ("11111111", '01234567')

print ('\n\tТокен (' + lab + '), slot=' + str(slotid) +  ' готов к использованию. Храните в секрете PIN-коды\n')
tinfo = t1.tokinfo()
for ll in tinfo:
    for key in ll:
        print (key + ': ' + ll[key])
print ('Флаги токена и слота: ' + str(t1.flags))
del t1
quit ()




