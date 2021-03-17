#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import pyp11
from Token import Token

print("Генерация ключевой пары, подпись, проверка подписи и уничтожение объектв\n")

#Параметры для ключей
gost2012_512 = ['1.2.643.7.1.2.1.2.1', '1.2.643.7.1.2.1.2.2', '1.2.643.7.1.2.1.2.3']
gost2012_256 = ['1.2.643.2.2.35.1', '1.2.643.2.2.35.2',  '1.2.643.2.2.35.3',  '1.2.643.2.2.36.0', '1.2.643.2.2.36.1', '1.2.643.7.1.2.1.1.1', '1.2.643.7.1.2.1.1.2', '1.2.643.7.1.2.1.1.3', '1.2.643.7.1.2.1.1.4']
gost2001 = ['1.2.643.2.2.35.1', '1.2.643.2.2.35.2',  '1.2.643.2.2.35.3',  '1.2.643.2.2.36.0', '1.2.643.2.2.36.1']
#Тип ключа
typekey = ['g12_256', 'g12_512']

#Для Linux
lib = '/usr/local/lib64/libls11sw2016.so'
#Облачный токен
#lib = '/usr/local/lib64/libls11cloud.so'
#Аппаратный токен
#lib = '/usr/local/lib64/librtpkcs11ecp_2.0.so'
#Для Windows
#lib='C:\Temp\ls11sw2016.dll'

#Загружаем библиотеку
aa = pyp11.loadmodule(lib)

#Создаем объект токен
slot = 0
#For rabota
sn = '228CBB83AEC1EA19'
#For dom
#sn = '50A333C9E79D9FD6'

#t1 = Token(aa, lab, slot)
t1 = Token(aa, slot, sn)
if (t1.returncode != ''):
    print ('Ошибка создания объекта токена')
    print (t1.returncode)
#Уничтожение объекта
    del t1
    quit()
    
#print (aa)
#user-pin
userpin = '01234567'
newpin = '12345678'
#userpin = '12345678'

t1.changeuserpin(userpin, newpin)
t1.changeuserpin(newpin, userpin)

#Логинимся на токене
ll, status = t1.login(userpin)

if (status != ''):
    print (status)
    print('Не удалось создать ключевую пару 0. Проблемы с login')
    if (status == 'PKCS11_ERROR USER_PIN_NOT_INITIALIZED'):
        print('Проблемы с login. Инициализируем userpin!')
        sopin = '87654321'
        ret, stat = t1.inituserpin(sopin, sopin)
        t1.changeuserpin(sopin, userpin)
        ll, status = t1.login(userpin)
    else:
        print('Не удалось создать ключевую пару 0. Проблемы с login')
        quit()
key_type = typekey[1]
par_key = gost2012_512[0]
labkey = 'key_512'

genkey,status = t1.keypair(key_type, par_key, labkey)
if (status != ''):
    print('Неудалось создать ключевую пару 1')
    print (status)
    quit()

print ('\tСгенерировали ключевую пару: ' + key_type + ' c параметром: ' + par_key + ' и меткой: ' + labkey)
for key in genkey.keys():
    print (key + ': ' + genkey.get(key))

hpubkey = genkey.get("hobj_pubkey")
hprivkey = genkey.get("hobj_privkey")
pubkeyinfo = genkey.get("pubkeyinfo")
pkcs11_id = genkey.get("pkcs11_id")

ckmpair='CKM_GOSTR3410_512'
print ('\tСчитаем хэш для подписи')
digest_hex, stat = t1.digest ("stribog512", "12345678900987654321")
if (stat != ''):
    print('Неудалось посчитать хэш')
    print (stat)
    quit()

print (digest_hex)
print ('\tПодписываем по handle закрытого ключа')
#Для подписания используем handle закрытого ключа
sign_hex, stat = t1.sign(ckmpair, digest_hex, hprivkey)
if (stat != ''):
    print (stat)
    quit()
#Для подписания используем CKA_ID закрытого ключа
sign1_hex1, stat = t1.sign(ckmpair, digest_hex, pkcs11_id)
print ('\tПодписываем по pkcs11_id (CKA_ID)  закрытого ключа')
if (stat != ''):
    print (stat)
    quit()
print (sign1_hex1)
print ('Проверка 1-ой подписи')
verify, stat = t1.verify(digest_hex, sign1_hex1, pubkeyinfo)
if (stat != ''):
    print ('Прерывание при verify 1: ' + stat)
if (verify == 1):
    print ('Подпись верна')
else:
    print ('Подпись не верна')

print ('Проверка 2-ой подписи')
verify, stat = t1.verify(digest_hex, sign1_hex1, pubkeyinfo)
#verify, stat = t1.verify(digest_hex, pubkeyinfo, sign1_hex1)
if (stat != ''):
    print ('Прерывание при verify 2: ' + stat)
if (verify == 1):
    print ('Подпись верна')
else:
    print ('Подпись не верна')
    print (verify)
#Rename key
label = 'key_512_new'
dd = dict(pkcs11_id=pkcs11_id, pkcs11_label=label)
print ("Список открытых ключей на токене (наш ключ с меткой key_512) ")
#lobj = pyp11.listobjects(aa, 0, 'pubkey')
lobj, stat = t1.listobjects('pubkey')
for lo in lobj:
    for key in lo:
        print ('\t' + key + ': ' + lo[key])
print ('Переименовывакм ключи с меткой: ' + labkey + ' на ' + label)
t1.rename('key', pkcs11_id, label)
#t1.changeckaid('key', pkcs11_id, '1111111111')
print ("Список открытых ключей на токене после переименования")
lobj, stat = t1.listobjects('pubkey')
for lo in lobj:
    for key in lo.keys():
        print ('\t' + key + ': ' + lo[key])

#Delete keyPair: private key and public key
#t1.delete('key', pkcs11_id)
#Or
#Delete private key
t1.delobject(hprivkey)
#Delete public key
print ("Удалили созданные ключи с меткой  key_512_new и hobj=" + hpubkey + ' и pkcs11_id=' + pkcs11_id )
t1.delobject(hpubkey)
lobj, stat = t1.listobjects('pubkey')
for lo in lobj:
    for key in lo.keys():
        print (key + ': ' + lo[key])

bb, stat = t1.logout()
if (stat != ''):
    print(stat)
ret, st = t1.tokinfo()
print (ret)
print ('SELG.INFOTOK = ' + str(t1.infotok))
print ('SELG.FLAGS = ' + str(t1.flags))
quit()
