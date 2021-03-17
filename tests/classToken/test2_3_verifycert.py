#!/usr/bin/python3
import pyp11
from Token import Token

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

print ('Разбираем корневой сертификат')
parseCA, stat = t1.parsecert (certCA_hex)
if (stat != ''):
    print (stat)
    quit()
print ('Разбираем сертификат пользователя')
parseHabre, stat = t1.parsecert (certHabr_hex)
if (stat != ''):
    print (stat)
    quit()
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
hashTbs_hex, stat = t1.digest("stribog512", tbsHabrDer)
if (stat != ''):
    print (stat)
    quit()
#hashTbs_hex, stat = t1.digest("stribog256", tbsHabrDer)
verify, stat = t1.verify(hashTbs_hex, parseHabre.get('signature'), parseCA.get('pubkeyinfo'))
#verify, stat = t1.verify(hashTbs_hex, parseHabre.get('signature'), parseHabre.get('pubkeyinfo'))
if (stat != ''):
    print ('Ошибка при проверке подписи:')
    print (stat)
    quit()
if (verify != 1):
    print ('Подпись сертификата не прошла проверку')
    quit()
print ('Подпись сертификата прошла проверку')
quit()




