import sys
import pyp11

class Token:
  def __init__ (self, handlelp11, slottoken, serialnum):
    flags = ''
    self.pyver = sys.version[0]
    if (self.pyver == '2'):
        print ('Только для python3')
        quit()
#Сохраняем handle библиотеки PKCS#11
    self.handle = handlelp11
#Сохраняем номер слота с токеном
    self.slotid = slottoken
#Сохраняем серийный номер токена
    self.sn = serialnum
#Проверяем наличие в указанном слоте с токена с заданным серийным номером
    ret, stat = self.tokinfo()
#Проверяем код возврата
    if (stat != ''):
#Возвращаем информацию об ошибке
        self.returncode = stat
        return
#Экземпляр класса (объект) успешно создан

  def tokinfo(self):
    status = ''
#Получаем список слотов
    try:
        slots = pyp11.listslots(self.handle)
    except:
#Проблемы с библиотекой токена
        e = sys.exc_info()[1]
        e1 = e.args[0]
        dd = ''
        status = e1
        return (dd, status)
    status = ''
#Ищем заданный слот с указанным  токеном
#Перебираем слоты
    for v in slots:
#Ищем заданный слот
            if (v[0] != self.slotid):
                status = "Ошибочный слот"
                continue
            self.returncode = ''
#Список флагов текущего слота
            self.flags = v[2]
#Проверяем наличие в стоке токена
            if (self.flags.count('TOKEN_PRESENT') !=0):
#Проверяем серийный номер токена
                tokinf = v[3]
                sn = tokinf[3].strip()
                if (self.sn != sn):
                    print ('Серийный номер токена=\"' + sn + '\" не совпадает с заданным \"' + self.sn + '\"')
                    status = "Плохой серийный номер"
                    dd = ''
                    return (dd, status)
                status = ''
                break
            else:
                dd = ''
                status = "В слоте нет токена"
                return (dd, status)
    tt = tokinf
    dd = dict(Label=tt[0].strip())
    dd.update(Manufacturer=tt[1].strip())
    dd.update(Model=tt[2].strip())
    dd.update(SerialNumber=tt[3].strip())
    self.infotok = dd
    return (dd, status)

  def listcerts(self):
    try:
        status = ''
        lcerts = pyp11.listcerts(self.handle, self.slotid)
    except:
#Проблемы с библиотекой токена
        e = sys.exc_info()[1]
        e1 = e.args[0]
        lcerts = ''
        status = e1
    return (lcerts, status)
  def listobjects(self, type1, value = '' ):
    try:
        status = ''
        if (value == ''):
    	    lobjs = pyp11.listobjects(self.handle, self.slotid, type1)
        else:
    	    lobjs = pyp11.listobjects(self.handle, self.slotid, type1, value)
    except:
#Проблемы с библиотекой токена
        e = sys.exc_info()[1]
        e1 = e.args[0]
        lobjs = ''
        status = e1
    return (lobjs, status)
  def rename(self, type, pkcs11id, label):
    try:
        status = ''
        dd = dict(pkcs11_id=pkcs11id, pkcs11_label=label)
        ret = pyp11.rename(self.handle, self.slotid, type, dd)
    except:
#Проблемы с библиотекой токена
        e = sys.exc_info()[1]
        e1 = e.args[0]
        ret = ''
        status = e1
    return (ret, status)

  def changeckaid(self, type, pkcs11id, pkcs11idnew):
    try:
        status = ''
        dd = dict(pkcs11_id=pkcs11id, pkcs11_id_new=pkcs11idnew)
        ret = pyp11.rename(self.handle, self.slotid, type, dd)
    except:
#Проблемы с библиотекой токена
        e = sys.exc_info()[1]
        e1 = e.args[0]
        ret = ''
        status = e1
    return (ret, status)
  def login(self, userpin):
    try:
        status = ''
        bb = pyp11.login (self.handle, self.slotid, userpin)
    except:
        e = sys.exc_info()[1]
        e1 = e.args[0]
        bb = 0
        status = e1
    return (bb, status)
  def logout(self):
    try:
        status = ''
        bb = pyp11.logout (self.handle, self.slotid)
    except:
        e = sys.exc_info()[1]
        e1 = e.args[0]
        bb = 0
        status = e1
    return (bb, status)
  def keypair(self, typek, paramk, labkey):
#Параметры для ключей
    gost2012_512 = ['1.2.643.7.1.2.1.2.1', '1.2.643.7.1.2.1.2.2', '1.2.643.7.1.2.1.2.3']
    gost2012_256 = ['1.2.643.2.2.35.1', '1.2.643.2.2.35.2',  '1.2.643.2.2.35.3',  '1.2.643.2.2.36.0', '1.2.643.2.2.36.1', '1.2.643.7.1.2.1.1.1', '1.2.643.7.1.2.1.1.2', '1.2.643.7.1.2.1.1.3', '1.2.643.7.1.2.1.1.4']
    gost2001 = ['1.2.643.2.2.35.1', '1.2.643.2.2.35.2',  '1.2.643.2.2.35.3',  '1.2.643.2.2.36.0', '1.2.643.2.2.36.1']
#Тип ключа
    typekey = ['g12_256', 'g12_512', 'gost2001']
    genkey = ''
    if (typek == typekey[0]):
    	gost = gost2012_256
    elif (typek == typekey[1]):
    	gost = gost2012_512
    elif (typek == typekey[2]):
    	gost = gost2001
    else:
    	status = 'Неподдерживаемый тип ключа'
    	return (genkey, status)
    if (gost.count(paramk) == 0) :
    	status = 'Неподдерживаемые параметры ключа'
    	return (genkey, status)
    try:
    	status = ''
    	genkey = pyp11.keypair(self.handle, self.slotid, typek, paramk, labkey)
    except:
#Не удалось создать ключевую паруG
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
    	print (e1)
#Возвращаеи текст ошибки
    	status = e1
    return (genkey, status)
  def digest(self, typehash, source):
#Считаем хэш
    try:
        status = ''
        digest_hex = pyp11.digest (self.handle, self.slotid, typehash, source)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки
    	status = e1
    	digest_hex = ''
    return (digest_hex, status)
#Формирование подписи
  def sign(self, ckmpair, digest_hex, idorhandle):
#Для подписи можно использовать CKA_ID или handle закрытого ключа
    try:
        status = ''
        sign_hex = pyp11.sign(self.handle, self.slotid, ckmpair, digest_hex, idorhandle)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#    	print (e1)
#Возвращаеи текст ошибки в словаре
    	status = e1
    	sign_hex = ''
    return (sign_hex, status)
#Проверка подписи
  def verify(self, digest_hex, sign_hex, pubkeyinfo):
#Для подписи можно использовать CKA_ID или handle закрытого ключа
    try:
        status = ''
        verify = pyp11.verify(self.handle, self.slotid, digest_hex, sign_hex, pubkeyinfo)
#        verify = pyp11.verify(self.handle, self.slotid, sign1_hex, sign1_hex, pubkeyinfo)
    except:
#    	print('Не удалось создать ключевую пару')
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#    	print (e1)
#Возвращаеи текст ошибки в status
    	verify = 0
    	status = e1
    return (verify, status)

#Инициализировать токен
  def inittoken(self, sopin, labtoken):
    try:
        status = ''
        dd = pyp11.inittoken (self.handle, self.slotid, sopin, labtoken)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = 0
    	status = e1
    return (dd, status)
#Инициализировать пользовательский PIN-код
  def inituserpin(self, sopin, userpin):
    try:
        status = ''
        dd = pyp11.inituserpin (self.handle, self.slotid, sopin, userpin)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = 0
    	status = e1
    return (dd, status)
#Сменить пользовательский PIN-код
  def changeuserpin(self, oldpin, newpin):
    try:
        status = ''
        dd = pyp11.setpin (self.handle, self.slotid, 'user', oldpin, newpin)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = 0
    	status = e1
    self.closesession ()
    return (dd, status)
  def closesession(self):
    try:
        status = ''
        dd = pyp11.closesession (self.handle)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = 0
    	status = e1
    return (dd, status)
  def parsecert(self, cert_der_hex):
    try:
        status = ''
        dd = pyp11.parsecert (self.handle, self.slotid, cert_der_hex)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = ''
    	status = e1
    return (dd, status)
  def importcert(self, cert_der_hex, labcert):
    try:
        status = ''
        dd = pyp11.importcert (self.handle, self.slotid, cert_der_hex, labcert)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = ''
    	status = e1
    return (dd, status)
  def delobject(self, hobject):
    try:
        status = ''
        hobjc = dict(hobj=hobject)
        dd = pyp11.delete(self.handle, self.slotid, 'obj', hobjc)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = ''
    	status = e1
    return (dd, status)
  def delete(self, type, pkcs11id):
    if (type == 'obj'):
        dd = ''
        status = 'delete for type obj use nethod delobject'
        return (dd, status)
    try:
        status = ''
        idobj = dict(pkcs11_id=pkcs11id)
        dd = pyp11.delete(self.handle, self.slotid, type, idobj)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = ''
    	status = e1
    return (dd, status)
  def listmechs(self):
    try:
        status = ''
        dd = pyp11.listmechs (self.handle, self.slotid)
    except:
    	e = sys.exc_info()[1]
    	e1 = e.args[0]
#Возвращаеи текст ошибки в status
    	dd = ''
    	status = e1
    return (dd, status)
