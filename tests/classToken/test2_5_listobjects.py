#!/usr/bin/python3
import sys
import pyp11
from Token import Token
    
print('Работа с функцией pyp11listobjects')

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

#Создаем объект токен
slot = 0
#For rabota
sn = '228CBB83AEC1EA19'
#For dom
#sn = '50A333C9E79D9FD6'

t1 = Token(aa, slot, sn)
if (t1.returncode != ''):
    print ('Ошибка создания объекта токена')
    print (t1.returncode)
#Уничтожение объекта
    del t1
    quit()

userpin = '01234567'
bb, stat = t1.login (userpin)
if (stat != ''):
    print ('Ошибка при login')
    print (stat)
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
lm, stat = t1.listobjects(type, 'value')
if (stat != ''):
    print ('Ошибка при listobjects')
    print (stat)
    quit()
print('Работа с listobjects: ' + type)
i =0
for obj in lm:
    print (str(i) + '-ый ' + tobj)
    for key in obj.keys():
        print ('\t' + key + ': ' + obj[key])
    i += 1
#lm, stat = t1.listobjects('cert', 'value')
#print('Работа с listobjects cert value:')
lm, stat = t1.listobjects('pubkey', 'value')
if (stat != ''):
    print ('Ошибка при listobjects value')
    print (stat)
    quit()
print('Работа с listobjects pubkey value:')
i =0
for obj in lm:
    print (str(i) + '-ый объект')
    for key in obj.keys():
        print ('\t' + key + ': ' + obj[key])
    i += 1
bb, stat = t1.logout()
