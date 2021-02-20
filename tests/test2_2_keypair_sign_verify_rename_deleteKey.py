#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import time
import pyp11

print("Генерация ключевой пары, подпись, проверка подписи и уничтожение объектв\n")

start_time = time.time()

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
#print (aa)
#user-pin
userpin = '01234567'
try:
    bb = pyp11.login (aa, 0, userpin)
except:
    print('Except login: ')
    e = sys.exc_info()[1]
    e1 = e.args[0]
    print (e1)
    quit()
key_type = typekey[1]
par_key = gost2012_512[0]
labkey = 'key_512'
try:
    genkey = pyp11.keypair(aa, 0, key_type, par_key, labkey)
except:
    print('Неудалось создать ключевую пару')
    e = sys.exc_info()[1]
    e1 = e.args[0]
    print (e1)
    quit()
print ('\tСгенерировали ключевую пару: ' + key_type + ' c параметром: ' + par_key + ' и меткой: ' + labkey)
#print (genkey.keys())
for key in genkey.keys():
    print (key + ': ' + genkey.get(key))

hpubkey = genkey.get("hobj_pubkey")
hprivkey = genkey.get("hobj_privkey")
pubkeyinfo = genkey.get("pubkeyinfo")
pkcs11_id = genkey.get("pkcs11_id")

ckmpair='CKM_GOSTR3410_512'
print ('\tСчитаем хэш для подписи')
digest_hex = pyp11.digest (aa, 0, "stribog512", "12345678900987654321")
print (digest_hex)
print ('\tПодписываем по handle закрытого ключа')
#Для подписания используем handle закрытого ключа
sign1_hex = pyp11.sign(aa, 0, ckmpair, digest_hex, hprivkey)
print (sign1_hex)
#Для подписания используем CKA_ID закрытого ключа
sign1_hex1 = pyp11.sign(aa, 0, ckmpair, digest_hex, pkcs11_id)
print ('\tПодписываем по pkcs11_id (CKA_ID)  закрытого ключа')
print (sign1_hex1)
print ('Проверка 1-ой подписи')
verify = pyp11.verify(aa, 0,  digest_hex, sign1_hex, pubkeyinfo)
if (verify == 1):
    print ('Подпись верна')
else:
    print ('Подпись не верна')
print ('Проверка 2-ой подписи')
verify = pyp11.verify(aa, 0,  digest_hex, sign1_hex1, pubkeyinfo)
if (verify == 1):
    print ('Подпись верна')
else:
    print ('Подпись не верна')

#Rename key
label = 'key_512_new'
dd = dict(pkcs11_id=pkcs11_id, pkcs11_label=label)
print ("Список открытых ключей на токене (наш ключ с меткой key_512) ")
lobj = pyp11.listobjects(aa, 0, 'pubkey')
for lo in lobj:
    for key in lo:
        print ('\t' + key + ': ' + lo[key])
print ('Переименовывакм ключи с меткой: ' + labkey + ' на ' + label)
pyp11.rename(aa, 0, 'key', dd)
print ("Список открытых ключей на токене после переименования")
lobj = pyp11.listobjects(aa, 0, 'pubkey')
for lo in lobj:
    for key in lo.keys():
        print ('\t' + key + ': ' + lo[key])

#Delete keyPair: private key and public key
dd = dict(pkcs11_id=pkcs11_id)
#pyp11.delete(aa, 0, 'key', dd)
#quit()

#Or
#Delete private key
dd = dict(hobj=hprivkey)
pyp11.delete(aa, 0, 'obj', dd)
#Delete public key
dd = dict(hobj=hpubkey)
print ("Удалили созданные ключи с меткой  key_512_new и hobj=" + hpubkey + ' и pkcs11_id=' + pkcs11_id )
pyp11.delete(aa, 0, 'obj', dd)
lobj = pyp11.listobjects(aa, 0, 'pubkey')
for lo in lobj:
    for key in lo.keys():
        print (key + ': ' + lo[key])

bb = pyp11.logout (aa, 0)

quit()
