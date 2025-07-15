"""
UOV: Unbalanced Oil and Vinegar
"""

import random
from Crypto.Cipher  import AES
from Crypto.Hash    import SHAKE256
import galois
from Crypto.Hash.SHAKE256 import SHAKE256_XOF


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
    self.__GF  = galois.GF(self.__GF_bitlen)
    self.__n   = n       # PUB_n
    self.__m   = m       # PUB_m
    self.__q   = q       
    self.__v   = n - m   # V

    self.__p1_sz = self.__m * self.__upper_triangular(self.__v)    #   _PK_P1_BYTE
    self.__p2_sz = ( self.__m ** 2 ) * self.__v                    #   _PK_P2_BYTE
    # self.__p3_sz = self.m * self.__upper_triangular(self.__m)    #   _PK_P3_BYTE

    # self.__seed_sk: int = random.getrandbits( self.__sk_seed_bitlen )
    # self.__seed_pk: int = random.getrandbits( self.__pk_seed_bitlen )
    

    # self.__expand_sk()


  # def get_O(self) -> list:
  #   return self.__O

  def __aes128ctr(self, key: int, l: int, ctr: int = 0) -> bytes:
    """ aes128ctr(key, l): Internal hook."""
    """ Генерирует последовтельность для публичного ключа"""
    iv: bytes = b'\x00' * 12
    aes       = AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=ctr)
    return aes.encrypt(b'\x00' * l)


  def __upper_triangular(self, N: int) -> int:
    """ return count non-zero elements in Upper Triangular Matrix"""
    """ Возвращает число ненулевых элементов в верхнетреугольной матрице"""
    return N * ( N + 1 ) // 2


  def __expand_p(self, seed: int) -> tuple:
    """ UOV.ExpandP() """
    pk = self.__aes128ctr(seed, self.__p1_sz + self.__p2_sz)
    return (pk[0:self.__p1_sz], pk[self.__p1_sz:]) 


  def __expand_sk(self, seed_sk):
    """
    Расширяет seed секретного ключа в матрицу O
    
    Args:
      seedsk: seed длиной sk_seed_len бит
      n, m  : параметры UOV
      q     : размер поля (16 или 256)
    
    Returns:
      Матрица O размера (n-m) × m
    """
    shake: SHAKE256_XOF = SHAKE256.new(b"{seed_sk:=b}")
    esk                 = shake.read(32)
    
    # Используем SHAKE256 для генерации псевдослучайных данных
    # Генерируем матрицу O в column-major порядке
    self.__O = []
    

  def __expand_pk(self, pk):
    """ UOV.ExpandPK(cpk). """
    seed_pk     =   pk[:self.seed_pk_sz]
    p3          =   pk[self.seed_pk_sz:]
    (p1, p2)    =   self.__expand_p(seed_pk)
    epk         =   p1 + p2 + p3
    return epk


############################
###    Public methods    ###
############################


  def multiple_over_GF(self, lhs: int, rhs: int) -> int:
    """ Перемножение чисел над полем Галуа"""
    return int(self.__GF(lhs) * self.__GF(rhs)) 


  def keygen(self):
    """ UOV.classic.KeyGen(). """
    """ Генерация ключей """

    seed_sk: int = random.getrandbits( self.__sk_seed_bitlen )
    # self.__seed_pk: int = random.getrandbits( self.__pk_seed_bitlen )

    # seed_sk     =   self.rbg(self.seed_sk_sz)
    seed_pk_so  =   self.shake256(seed_sk, self.seed_pk_sz + self.so_sz)
    seed_pk     =   seed_pk_so[:self.seed_pk_sz]
    so          =   seed_pk_so[self.seed_pk_sz:]
    (p1, p2)    =   self.expand_p(seed_pk)
    (sks, p3)   =   self.calc_f2_p3(p1, p2, so)

    #   public key compression
    if  self.pkc:
      pk  =   seed_pk + p3                #   cpk
    else:
      pk  =   p1 + p2 + p3                #   epk

    #   secret key compression
    if  self.skc:
      sk  =   seed_sk                     #   csk
    else:
      sk  =   seed_sk + so + p1 + sks     #   esk

    return (pk, sk)
