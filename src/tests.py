from UOV import uov
from uov_attack_xl import *


def test_uov_V():
  import galois
  q = 256
  GF256 = galois.GF(q)
  
  signer = uov()
  cpk, csk = signer.keygen()
  esk = signer.expand_SK(csk)

  msg = b"example message"
  sig = signer.sign(esk, msg)
  print("[TEST] Valid signature:", signer.verify(cpk, msg, sig))

  # Создаем неправильную подпись для того же сообщения
  if sig is not None:
    s, salt = sig

    wrong_s = s.copy()
    wrong_s[0] += GF256(1)  # Изменяем первый элемент подписи
    wrong_sig = (wrong_s, salt)
    print("[TEST] Invalid signature:", ( not signer.verify(cpk, msg, wrong_sig) ))
  else:
    print("[ERROR] Failed to generate initial signature")


def test_uov_Ip():
  import galois
  q = 256
  GF256 = galois.GF(q)
  
  signer = uov(n=112, m=44, q=q)
  cpk, csk = signer.keygen()
  esk = signer.expand_SK(csk)

  msg = b"example message"
  sig = signer.sign(esk, msg)
  print("[TEST] Valid signature:", signer.verify(cpk, msg, sig))

  # Создаем неправильную подпись для того же сообщения
  if sig is not None:
    s, salt = sig

    wrong_s = s.copy()
    wrong_s[0] += GF256(1)  # Изменяем первый элемент подписи
    wrong_sig = (wrong_s, salt)
    print("[TEST] Invalid signature:", ( not signer.verify(cpk, msg, wrong_sig) ))
  else:
    print("[ERROR] Failed to generate initial signature")


def test_attack_UOV_Ip():
    """
    Простой тест атаки на UOV-Ip
    """
    print("=== Тест UOV reconciliation attack ===")

    q: int = 256
    n: int = 112
    m: int = 44
    
    signer = uov(n=n, m=m, q=q)


    # Генерируем ключи UOV для тестирования
    print("Генерируем тестовые ключи...")
    cpk, csk = signer.keygen()
    epk = signer.get_epk(cpk)

    print(f"Ключи созданы. Размер открытого ключа: {len(epk)} полиномов")

    # Создаем объект атаки
    attack = UOVReconciliationAttack(epk, n, m)

    # Запускаем атаку
    result = attack.reconciliation_attack_xl(max_xl_degree=3)

    if result is not None:
        F_recovered, M_T = result
        print("Атака завершена успешно!")
        print(f"Восстановлено {len(F_recovered)} полиномов")
        print(f"Размер матрицы преобразования: {M_T.shape}")
    else:
        print("Атака не удалась")


def test_attack_small():
    """
    Тест атаки на маленьких параметрах для отладки
    """
    print("=== Тест UOV reconciliation attack (маленькие параметры) ===")

    # Маленькие параметры для быстрого тестирования
    test_n = 6  # общее количество переменных
    test_m = 3  # количество полиномов (oil переменных)
    test_v = test_n - test_m  # 3 vinegar переменных

    print(f"Тестовые параметры: n={test_n}, m={test_m}, v={test_v}")

    # Создаем простые тестовые полиномы вручную
    test_polynomials = []
    for i in range(test_m):
        # Создаем случайную матрицу 6x6 для каждого полинома
        poly_matrix = GF256.Random((test_n, test_n))
        # Делаем матрицу верхнетреугольной (для квадратичной формы)
        for row in range(test_n):
            for col in range(row):
                poly_matrix[row, col] = GF256(0)  # нули под диагональю
        test_polynomials.append(poly_matrix)

    print(f"Созданы тестовые полиномы: {len(test_polynomials)} матриц {test_n}x{test_n}")

    # Создаем объект атаки с тестовыми параметрами
    attack = UOVReconciliationAttack(test_polynomials, test_n, test_m)

    # Запускаем атаку
    result = attack.reconciliation_attack_xl(max_xl_degree=2)  # меньшая степень для скорости

    if result is not None:
        F_recovered, M_T = result
        print("Атака завершена успешно!")
        print(f"Восстановлено {len(F_recovered)} полиномов")
        print(f"Размер матрицы преобразования: {M_T.shape}")
    else:
        print("Атака не удалась")
