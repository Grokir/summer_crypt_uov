from UOV import uov
# from uov_attack_xl import *
from xl_alg import *
# from test_solve_ls import gauss_elimination



def test_uov_Ip():
  import galois

  q = 256
  n = 112
  m = 44
  
  GF256 = galois.GF(q)
  
  signer = uov(n=n, m=m, q=q)
  cpk, csk = signer.keygen()
  esk = signer.expand_SK(csk)

  msg = b"example message"
  sig = signer.sign(esk, msg)
  print("[TEST]  Valid   signature:", signer.verify(cpk, msg, sig))

  # Создаем неправильную подпись для того же сообщения
  if sig is not None:
    s, salt = sig

    wrong_s = s.copy()
    wrong_s[0] += GF256(1)  # Изменяем первый элемент подписи
    wrong_sig = (wrong_s, salt)
    print("[TEST]  Invalid signature:", ( not signer.verify(cpk, msg, wrong_sig) ))
  else:
    print("[ERROR] Failed to generate initial signature")


def test_uov_Is():
  import galois
  
  q = 16
  n = 160
  m = 64

  GF256 = galois.GF(q)
  
  signer = uov(n=n, m=m, q=q)
  cpk, csk = signer.keygen()
  esk = signer.expand_SK(csk)

  msg = b"example message"
  sig = signer.sign(esk, msg)
  print("[TEST]  Valid   signature:", signer.verify(cpk, msg, sig))

  # Создаем неправильную подпись для того же сообщения
  if sig is not None:
    s, salt = sig

    wrong_s = s.copy()
    wrong_s[0] += GF256(1)  # Изменяем первый элемент подписи
    wrong_sig = (wrong_s, salt)
    print("[TEST]  Invalid signature:", ( not signer.verify(cpk, msg, wrong_sig) ))
  else:
    print("[ERROR] Failed to generate initial signature")



def test_uov_III():
  import galois
  
  q = 256
  n = 184
  m = 72

  GF256 = galois.GF(q)
  
  signer = uov(n=n, m=m, q=q)
  cpk, csk = signer.keygen()
  esk = signer.expand_SK(csk)

  msg = b"example message"
  sig = signer.sign(esk, msg)
  print("[TEST]  Valid   signature:", signer.verify(cpk, msg, sig))

  # Создаем неправильную подпись для того же сообщения
  if sig is not None:
    s, salt = sig

    wrong_s = s.copy()
    wrong_s[0] += GF256(1)  # Изменяем первый элемент подписи
    wrong_sig = (wrong_s, salt)
    print("[TEST]  Invalid signature:", ( not signer.verify(cpk, msg, wrong_sig) ))
  else:
    print("[ERROR] Failed to generate initial signature")


def test_uov_V():
  import galois
  
  q = 256
  
  GF256 = galois.GF(q)
  
  signer = uov()
  cpk, csk = signer.keygen()
  esk = signer.expand_SK(csk)

  msg = b"example message"
  sig = signer.sign(esk, msg)
  print("[TEST]  Valid   signature:", signer.verify(cpk, msg, sig))

  # Создаем неправильную подпись для того же сообщения
  if sig is not None:
    s, salt = sig

    wrong_s = s.copy()
    wrong_s[0] += GF256(1)  # Изменяем первый элемент подписи
    wrong_sig = (wrong_s, salt)
    print("[TEST]  Invalid signature:", ( not signer.verify(cpk, msg, wrong_sig) ))
  else:
    print("[ERROR] Failed to generate initial signature")



def test_attack_UOV_Ip():
    """
    Простой тест атаки на UOV-Ip
    """
    print("=== Тест UOV reconciliation attack ===")

    # UOV-Ip
    # q: int = 256
    # n: int = 112
    # m: int = 44

    # UOV-III
    q: int = 256
    n: int = 184
    m: int = 72

    # UOV-V
    # n: int = 244 
    # m: int = 96 
    # q: int = 256


    signer = uov(n=n, m=m, q=q)


    # Генерируем ключи UOV для тестирования
    print("Генерируем тестовые ключи...")
    cpk, csk = signer.keygen()
    epk = signer.get_epk(cpk)

    # print(epk)
    # return -1

    print(f"Ключи созданы. Размер открытого ключа: {len(epk)} полиномов")

    # Создаем объект атаки
    attack = UOVReconciliationAttack(public_key=epk, n=n, m=m, q=q)

    # Запускаем атаку
    result = attack.reconciliation_attack_xl(max_xl_degree=3)

    if result is not None:
        F_recovered, M_T = result
        print("Атака завершена успешно!")
        print(f"Восстановлено {len(F_recovered)} полиномов")
        print(f"Размер матрицы преобразования: {M_T.shape}")
        print(f"\n[+] F recovered: {F_recovered}")
    else:
        print("Атака не удалась")

    msg = b"Ex4mpl3 MESSAGE"
    # print(f"cpk = {cpk}")
    sig = attack.attack_sign(msg, F_recovered, M_T)
    
    print("[TEST] Valid signature:", signer.verify(cpk, msg, sig))

    

# def test_solve_Linear_System():
   