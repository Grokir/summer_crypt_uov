"""
UOV: Unbalanced Oil and Vinegar
"""

import random
import galois

from Crypto.Cipher  import AES      #К: ???
from Crypto.Hash    import SHAKE256

class uov_V:
  __GF_bitlen:      int = 256   # Размер поля Галуа
  __salt_bitlen:    int = 128
  __pk_seed_bitlen: int = 128
  __sk_seed_bitlen: int = 256


  def __init__(self, n:int=244, m:int=96, q:int=256) -> None:
    """
    default params:
      len  n = 244 bits 
      len  m =  96 bits 
      len  q = 256 bits
    """

    # Основные параметры
    self.__n = n       # PUB_n
    self.__m = m       # PUB_m
    self.__q = q       
    self.__v = n - m   # V

    # Генерируем seeds
    self.__seed_sk: int = random.getrandbits( self.__sk_seed_bitlen )
    self.__seed_pk: int = random.getrandbits( self.__pk_seed_bitlen )
    
    self.__p1_sz = self.__m * self.__upper_triangular(self.__v)    #   _PK_P1_BYTE
    self.__p2_sz = ( self.__m ** 2 ) * self.__v                    #   _PK_P2_BYTE
    # self.__p3_sz = self.m * self.upper_triangular(self.__m)    #   _PK_P3_BYTE

    # Инициализация поля Галуа 
    self.__GF = galois.GF(self.__GF_bitlen)
    
    self.__expand_sk()

    # def get_O(self) -> list:
    #   return self.__O
  def __aes128ctr(self, key, l, ctr=0) -> bytes:
    """ aes128ctr(key, l): Internal hook."""
    """ Генерирует последовтельность для публичного ключа"""
    iv  =   b'\x00' * 12
    aes =   AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=ctr)
    return aes.encrypt(b'\x00' * l)

  def __upper_triangular(self, N:int) -> int:
    """ return count non-zero elements in Upper Triangular Matrix"""
    """ Возвращает число ненулевых элементов в верхнетреугольной матрице"""
    return N * ( N + 1 ) // 2

  def __expand_p(self) -> tuple:
    return tuple()

  def __expand_sk(self):
    """
    Расширяет seed секретного ключа в матрицу O
    
    Args:
      seedsk: seed длиной sk_seed_len бит
      n, m  : параметры UOV
      q     : размер поля (16 или 256)
    
    Returns:
      Матрица O размера (n-m) × m
    """
    shake: SHAKE256_XOF = SHAKE256.new(b"{self.__seed_sk:=b}")
    esk                 = shake.read(32)
    
    # Используем SHAKE256 для генерации псевдослучайных данных
    # Генерируем матрицу O в column-major порядке
    self.__O = []
    for col in range(self.__m):  # для каждого столбца
      column = []
      for row in range((self.__n - self.__m)//8):  # для каждой строки в столбце
        print(f"n - m = {(self.__n - self.__m) // 8}")
        print(f"esk length = {len(b"{esk:=b}")}")
        return
        # Генерируем элемент поля
        if self.__q == 256:
          element = esk[row] % self.__q
        elif self.__q == 16:
          element = esk[row] % self.__q
        column.append(element)
      self.__O.append(column)

      #В комментраии ниже описание библиотеки поля Галуа
  """
  Библиотека galois - основные компоненты:

  1. Создание полей:
      GF256 = galois.GF(256)  # Поле из 256 элементов

  2. Создание элементов:
      a = GF256(123)          # Один элемент
      arr = GF256([1, 2, 3])  # Массив элементов

  3. Арифметические операции:
      c = a + b, d = a * b, e = a ** -1  # Сложение, умножение, обращение

  4. Операции с массивами:
      C = A @ B               # Умножение матриц
      inv_A = A.inv()         # Обращение матрицы

  5. Преобразования типов:
      num = int(a)            # Элемент поля → число
      a = GF256(123)          # Число → элемент поля

  6. Информация о поле:
      GF256.order             # 256 (размер поля)
      GF256.irreducible_poly  # Неприводимый полином

  7. Полезные функции:
      GF256.Random()          # Случайный элемент
      GF256.Zero(), GF256.One()  # Нуль и единица
  """
#Методы поля Галуа

  def gf_add(self, a: int, b: int) -> int:
    return int(self.__GF(a) + self.__GF(b))

  def gf_mul(self, a: int, b: int) -> int:
    return int(self.__GF(a) * self.__GF(b))

  """Обратный элемент"""
  def gf_invert(self, a: int) -> int:
    if a == 0:
        return 0
    return int(self.__GF(a) ** -1)

  """Создание массива элементов поля"""
  def gf_create_array(self, data: list):
    return self.__GF(data)

  """Умножение матриц"""
  def gf_mul_matr(self, A:list, B:list):
    # Если переданы обычные списки, преобразуем один раз
    if isinstance(A, list):
      A = self.__GF(A)
    if isinstance(B, list):
      B = self.__GF(B)

    return A @ B

  """Обращение матрицы"""
  def gf_invert_matr(self, A:list, B:list):
    if isinstance(A, list):
        A = self.__GF(A)
    try:
        return A.inv()
    except:
        return None

  """Транспонирование матрицы"""
  def gf_matr_trans(self, A):
    if isinstance(A, list):
        A = self.__GF(A)
    return A.T



    
