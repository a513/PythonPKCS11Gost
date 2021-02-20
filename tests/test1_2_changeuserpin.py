#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import pyp11

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
    slots = pyp11.listslots(libid)

#Проверяем, что заводской USER-PIN надо поменять 
if (flags.count('USER_PIN_TO_BE_CHANGED') > 0 ):
    print ('Требуется сменить пользовательский (use) PIN-код')
#    pyp11.logout(libid, 0)
    dd2 = pyp11.setpin (libid, 0, 'user',"11111111", '01234567')

print ('\n\tТокен (' + lab + '), slot=' + str(slotid) +  ' готов к использованию. Храните в секрете PIN-коды\n')
slots = pyp11.listslots(libid)
#print (slots[0])
i = 0
for slot in slots:
    print ('Информация о слоте: ' + str(i))
    i += 1
    print ('\tНомер слота: ' + str(slot[0]))
    print ('\tМетка токена в слоте: ' + slot[1])
    print ('\tФлаги слота и токена: ' + str(slot[2]))
    print ('\tИнформация о токене в стоте')
    tok = slot[3]
    print ('\t\tМетка токена: ' + tok[0])
    print ('\t\tПроизводитель токена: ' + tok[1])
    print ('\t\tМодель токена: ' + tok[2])
    print ('\t\tСерийный номер токена: ' + tok[3])

quit ()




