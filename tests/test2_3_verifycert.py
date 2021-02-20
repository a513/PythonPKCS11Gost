#!/usr/bin/python3
#-*- coding: utf-8 -*-

import pyp11

print('Проверка подписи сертификата')
#Библиотека для токена
lib = '/usr/local/lib64/libls11sw2016.so'
aa = pyp11.loadmodule(lib)
print (aa)
#Файл с корневым сертификатом в DER-кодировке
fileCA = "CA_12_512.der"
#Файл с сертификатов пользователя в DER-кодировке
fileUser = "habrCA_12_512.der"
#Читаем корневой серификат в DER-кодировке из файла
with open(fileCA, "rb") as f:
    certCA = f.read()
#Упаковываем der в hex
certCA_hex = bytes(certCA).hex()
#Читаем серификат пользователя в DER-кодировке из файла
with open(fileUser, "rb") as f:
    certHabr = f.read()
#Упаковываем der в hex
certHabr_hex = bytes(certHabr).hex()

print ('Разбираем корневой сертификат')
parseCA = pyp11.parsecert (aa, 0, certCA_hex)
print ('Разбираем сертификат пользователя')
parseHabre = pyp11.parsecert (certHabr_hex)
print (parseHabre.keys())
#Проверяем, что издатель сертификата совпадает с владельцем корневого сертификата
if (parseCA.get('subject') != parseHabre.get('issuer')):
    print ('Сертификат выдан на другом УЦ')
    quit()
print ('Сертификат выдан на данном УЦ')
#Переводим tbsCertificate пользователь в binary
tbs_hex = parseHabre.get('tbsCertificate')
tbsHabrDer = bytes(bytearray.fromhex(tbs_hex))
#tbsHabrDer = '1111'
#Получаем хэш для tbs-сертификата
hashTbs_hex = pyp11.digest(aa, 0, "stribog512", tbsHabrDer)
#hashTbs_hex = pyp11.digest(aa, 0, "stribog256", tbsHabrDer)
verify = pyp11.verify(aa, 0,  hashTbs_hex, parseHabre.get('signature'), parseCA.get('pubkeyinfo'))
#verify = pyp11.verify(aa, 0,  hashTbs_hex, parseHabre.get('signature'), parseHabre.get('pubkeyinfo'))
print (verify)
if (verify != 1):
    print ('Подпись сертификата не прошла проверку')
    quit()
print ('Подпись сертификата прошла проверку')
quit()




