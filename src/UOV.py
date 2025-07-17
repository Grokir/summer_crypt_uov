"""
UOV: Unbalanced Oil and Vinegar
"""

import random, galois, numpy as np
from Crypto.Cipher  import AES
from Crypto.Hash    import SHAKE256

class uov:
  __salt_bitlen:    int = 128
  __pk_seed_bitlen: int = 128
  __sk_seed_bitlen: int = 256


  def __init__(self, n:int=244, m:int=96, q:int=256) -> None:
    """
    default params:
      len  n = 244 bits 
      len  m =  96 bits 
      len  q = 256 bits # GF(q)
    """
    self.__q :int = q
    self.__GF     = galois.GF(self.__q)
    self.__n :int = n       # PUB_n
    self.__m :int = m       # PUB_m
    self.__v :int = n - m   # V

    self.__p1_sz =   self.__m * (self.__v * (self.__v + 1) // 2)
    self.__p2_sz = ( self.__m ** 2 ) * self.__v                     #   _PK_P2_BYTE
    

  def __aes128ctr(self, key: bytes, l: int, ctr: int = 0) -> bytes:
    """ aes128ctr(key, l): Internal hook."""
    """ Генерирует последовтельность для публичного ключа"""
    iv: bytes = b'\x00' * 12
    aes       = AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=ctr)
    return aes.encrypt(b'\x00' * l)


  def __expand_p(self, seed_pk: bytes) -> tuple:
    """ UOV.ExpandP() """
    pk = self.__aes128ctr(seed_pk, self.__p1_sz + self.__p2_sz)
    
    P1 = [self.__GF.Zeros((self.__v, self.__v)) for _ in range(self.__m)]
    P2 = [self.__GF.Zeros((self.__v, self.__m)) for _ in range(self.__m)]
    
    idx: int = 0
    positions = [(r, c) for c in range(self.__v) for r in range(c + 1)]
    for (row, col) in positions:
      for i in range(self.__m):
        P1[i][row, col] = pk[idx]
        idx += 1
    
    for col in range(self.__m):
      for row in range(self.__v):
        for i in range (self.__m):
          P2[i][row, col] = pk[idx]
          idx += 1
    
    return (P1, P2)     


  def __expand_sk(self, seed_sk: bytes):
    """
    UOV.ExpandSK(seed_sk)
    Расширяет seed секретного ключа в матрицу O
    
    Args:
      seedsk: seed длиной sk_seed_len бит
      n, m  : параметры UOV
      q     : размер поля (16 или 256)
    
    Returns:
      Матрица O размера (n-m) × m
    """
    shake: SHAKE256_XOF = SHAKE256.new(seed_sk)
    data:  list         = [shake.read(1)[0] for _ in range(self.__v * self.__m)]
    
    return self.__GF(data).reshape((self.__v, self.__m), order='F')

  
  def __expand_pk(self, cpk: tuple) -> list:
    """ UOV.ExpandPK(pk). """
    (seed_pk, P3) = cpk
    (P1, P2)      = self.__expand_p(seed_pk)
    epk: list     = []
    
    for i in range(self.__m):
      Pi = self.__GF.Zeros((self.__n, self.__n))
      Pi[:self.__v, :self.__v ] = P1[i]
      Pi[:self.__v,  self.__v:] = P2[i]
      Pi[ self.__v:, self.__v:] = P3[i]
      epk.append(Pi)
    
    return epk



#############################
###    Private methods    ###
###      mathematic       ###
#############################


  def __upper_triangular(self, P1, P2, O):
    """
    P3_i = Upper( - O^T·P1_i·O  -  O^T·P2_i )
    """
    OT = O.T
    ut_matr = []
    for i in range(self.__m):
      M = -(OT @ P1[i] @ O + OT @ P2[i])
      S = self.__GF.Zeros((self.__m, self.__m))
 
      for r in range(self.__m):
        for c in range(r, self.__m):
          if r == c:
            S[r, c] = M[r, c]
          else:
            S[r, c] = M[r, c] + M[c, r]
      ut_matr.append(S)

    return ut_matr


  def __get_matr_rank(self, matr) -> int:
    tmp_matr = matr.copy()
    rows, cols = tmp_matr.shape
    rank:int = 0
    for col in range(cols):
      pivot = next((r for r in range(rank, rows) if tmp_matr[r, col] != 0), None)
      
      if pivot is not None:
        tmp_matr[[rank, pivot]] = tmp_matr[[pivot, rank]]
        tmp_matr[rank] *= self.__GF(1) / tmp_matr[rank, col]
        
        for r in range(rows):
          if r != rank and tmp_matr[r, col] != 0:
            tmp_matr[r] -= tmp_matr[rank] * tmp_matr[r, col]
        
        rank += 1
    return rank



  def __matr_transpose(self, A):
    return self.__GF(A).T
  

  def __gauss_solve(self, A, b):
    """ Solve a system of linear equations in GF."""
    tmp_A = A.copy()
    tmp_b = b.copy().reshape(-1, 1)
    Ab = self.__GF(np.hstack([tmp_A, tmp_b]))
    n = tmp_A.shape[0]

    for i in range(n):
      pivot = next((r for r in range(i, n) if Ab[r, i] != 0), None)
      
      if ( pivot is None ):
        return None
      
      if ( pivot != i ):
        Ab[[i, pivot]] = Ab[[pivot, i]]
      
      Ab[i] *= self.__GF(1) / Ab[i, i]
      
      for r in range(n):
        if ( r != i ) and ( Ab[r, i] != 0 ):
          Ab[r] -= Ab[i] * Ab[r, i]
    
    return Ab[:, -1]
    
  
  def __quad_form(self, P, v): # Понадобится в алгоритме Sign
    """vᵀ·P·v в GF(q)."""
    return v @ (P @ v)


############################
###    Public methods    ###
############################


  def multiple_over_GF(self, lhs: int, rhs: int) -> int:
    """ Перемножение чисел над полем Галуа"""
    return int(self.__GF(lhs) * self.__GF(rhs)) 


  def expand_SK(self, csk: tuple) -> tuple:
    """
    UOV.ExpandSK: (seed_pk, seed_sk) → esk = (seed_sk, O, {P1_i}, {S_i})
    где S_i = (P1_i + P1_i^T)·O + P2_i
    * по методичке
    """

    (seed_pk, seed_sk)  = csk
    O                   = self.__expand_sk(seed_sk)
    (P1, P2)            = self.__expand_p (seed_pk)
    S: list             = [(P1[i] + P1[i].T) @ O + P2[i] for i in range(self.__m)]
    
    return (seed_sk, O, P1, S)
  

  def keygen(self):
    """ UOV.classic.KeyGen(). """
    """ Генерация ключей """

    seed_sk: int = random.randbytes( self.__sk_seed_bitlen // 8 )
    seed_pk: int = random.randbytes( self.__pk_seed_bitlen // 8 )

    O        = self.__expand_sk       (  seed_sk  )
    (P1, P2) = self.__expand_p        (  seed_pk  )
    P3       = self.__upper_triangular( P1, P2, O )
    
    return (seed_pk, P3), (seed_pk, seed_sk)
  

  def sign(self, esk:tuple, msg: bytes):
    (seed_sk, O, P1, S) = esk
    salt = random.randbytes(self.__salt_bitlen // 8)
    t = self.__GF(list(SHAKE256.new(msg + salt).read(self.__m)))

    cnt_rounds = 256

    for ctr in range(cnt_rounds):
      shake = SHAKE256.new(msg + salt + seed_sk + bytes([ctr]))
      v = self.__GF(list(shake.read(self.__v)))
      L = self.__GF.Zeros((self.__m, self.__m))
      
      for i in range(self.__m):
        L[i, :] = v @ S[i]
      
      if ( self.__get_matr_rank(L) < self.__m ):
        continue
        
      y   = self.__GF([self.__quad_form(P1[i], v) for i in range(self.__m)])
      rhs = t - y
      x   = self.__gauss_solve(L, rhs)
      s   = self.__GF.Zeros(self.__n)
      
      s     [:self.__v]     =  v
      O_bar                 =  self.__GF.Zeros((self.__n, self.__m))
      O_bar [:self.__v, :]  =  O
      O_bar [self.__v:, :]  =  self.__GF.Identity(self.__m)
      s                     += (O_bar @ x.reshape((self.__m, 1))).flatten()

      return (s, salt)

    return None
  

  def verify(self, cpk: tuple, msg: bytes, signature) -> bool:
    if ( signature is None ):
      return False
    
    (s, salt) = signature 
    epk = self.__expand_pk(cpk)
    t = self.__GF(list(SHAKE256.new(msg + salt).read(self.__m)))

    is_valid: bool = True

    for i, Pi in enumerate(epk):
      tmp = self.__quad_form(Pi, s) #sᵀ·Pi·s
      if ( tmp != t[i] ):
        is_valid = False
      
    return is_valid
  

  def get_epk(self, cpk: tuple):
    return self.__expand_pk(cpk)