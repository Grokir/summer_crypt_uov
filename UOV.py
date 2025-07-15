"""
UOV: Unbalanced Oil and Vinegar
"""

import random
from Crypto.Cipher  import AES
from Crypto.Hash    import SHAKE256

class uov_V:
  __GF_bitlen:      int = 256   # Galois field size
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

    self.__n = n       # PUB_n
    self.__m = m       # PUB_m
    self.__q = q       
    self.__v = n - m   # V

    self.__seed_sk: int = random.getrandbits( self.__sk_seed_bitlen )
    self.__seed_pk: int = random.getrandbits( self.__pk_seed_bitlen )

    self.__p1_sz = self.m * self.upper_triangular(self.__v)    #   _PK_P1_BYTE
    self.__p2_sz = ( self.m ** 2 ) * self.v                    #   _PK_P2_BYTE
    # self.__p3_sz = self.m * self.upper_triangular(self.__m)    #   _PK_P3_BYTE


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
    