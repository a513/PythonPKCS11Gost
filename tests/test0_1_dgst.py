#!/usr/bin/python3
#-*- coding: utf-8 -*-

import sys
import time

# пути до модуля _test
#sys.path.append('.')
#sys.path.append('build/lib/')
#sys.path.append('../../lib/')

import pyp11

start_time = time.time()


##
# Работа с функциями
##
    
print('Работа с функциями dgst:')
# Время работы
t1 = time.time()
i = 0
j = 1000
while (i < j):
#    dd = pyp11.dgst ("stribog512", "12345678900987654321")
    dd = pyp11.dgst ('stribog512', '12345678900987654321')
    i += 1
t2 = time.time()
print("--- {} seconds --- digest stribog512 from module".format(t2 - t1 ))
print (dd)
# Время работы
t1 = time.time()
i = 0
while (i < j):
    dd1 = pyp11.dgst ('stribog256', '12345678900987654321')
    i += 1
t2 = time.time()
print("--- {} seconds --- digest stribog256 from module".format(t2 - t1 ))
print (dd1)
