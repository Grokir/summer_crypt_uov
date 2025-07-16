"""
UOV: Unbalanced Oil and Vinegar
"""

import random
from Crypto.Cipher import AES
from Crypto.Hash import SHAKE256
import galois
from Crypto.Hash.SHAKE256 import SHAKE256_XOF

"""
Класс для реализации криптосистемы UOV
"""
class uov_V:

    # Константы размеров в битах
    __GF_bitlen: int = 256       # размер поля Галуа
    __salt_bitlen: int = 128     # размер соли
    __pk_seed_bitlen: int = 128  # размер seed для публичного ключа(public key)
    __sk_seed_bitlen: int = 256  # размер seed для секретного ключа(secret key)

    """
    Инициализация параметров UOV
    """
    def __init__(self, n: int = 244, m: int = 96, q: int = 256) -> None:
        """
        Args:
            n (int): количество переменных (масленые и уксусные)
            m (int): количество уравнений (масляные компоненты)
            q (int): размер поля

        Параметры по умолчанию:
            len n = 244 bits
            len m = 96 bits
            len q = 256 bits
        """

        # Инициализация поля Галуа с помощью библиотеки galois
        self.__GF = galois.GF(self.__GF_bitlen)

        """Основные параметры схемы:
        PUB_n (self.__n) - общее количество переменных (масляных и уксусных), используемых в публичном ключе.
        PUB_m (self.__m) - количество уравнений (равно числу масляных переменных. Система переопределена), используемых в публичном ключе.
        q (self.__q) - размер поля (не масло+уксус, а размер поля Галуа)
        v (self.__v) - количество "уксусных" переменных
        """
        self.__n = n
        self.__m = m
        self.__q = q
        self.__v = n - m

        # Вычисление размеров(sz) компонентов публичного ключа
        """
        P_i =   [P1_i  P2_i]
                [0     P3_i]
                
                Где:

                P1 - верхняя левая часть (треугольная матрица размера v×v)
                P2 - верхняя правая часть (прямоугольная матрица размера v×m)
                P3 - нижняя правая часть (треугольная матрица размера m×m)
                
        (Методичка страница 12)
        """
        self.__p1_sz = self.__m * self.__upper_triangular(self.__v)    # _PK_P1_BYTE  #К: почему верхнетреугольная матрица?
        self.__p2_sz = (self.__m ** 2) * self.__v                      # _PK_P2_BYTE
        # self.__p3_sz = self.m * self.__upper_triangular(self.__m)    # _PK_P3_BYTE

        # Инициализация seed'ов
        # self.__seed_sk: int = random.getrandbits(self.__sk_seed_bitlen)
        # self.__seed_pk: int = random.getrandbits(self.__pk_seed_bitlen)

        # Расширение секретного ключа
        # self.__expand_sk()

    # Геттеры
    # def get_O(self) -> list:
    #     return self.__O

    """
    AES128-CTR генератор псевдослучайных данных
    """
    def __aes128ctr(self, key: int, l: int, ctr: int = 0) -> bytes:
        """
        Args:
            key (int): ключ шифрования
            l (int): длина выходной последовательности в байтах
            ctr (int): начальное значение счетчика (по умолчанию 0)

        Returns:
            bytes: псевдослучайная последовательность длиной l байт

        Note:
            Генерирует последовательность для публичного ключа
        """
        iv: bytes = b'\x00' * 12
        aes = AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=ctr)
        return aes.encrypt(b'\x00' * l)

    """
    Подсчет количества ненулевых элементов в верхнетреугольной матрице
    """
    def __upper_triangular(self, N: int) -> int:
        """
        Args:
            N (int): размер квадратной матрицы

        Returns:
            int: количество элементов в верхнем треугольнике (включая диагональ)

        Formula:
            N * (N + 1) / 2
        """

        return N * (N + 1) // 2

    """
    Расширение seed в компоненты P1 и P2 публичного ключа
    """
    def __expand_p(self, seed: int) -> tuple:
        """
        Args:
            seed (int): seed для генерации компонентов

        Returns:
            tuple: (P1, P2) - компоненты публичного ключа

        Note:
            Реализует алгоритм UOV.ExpandP()
        """
        pk = self.__aes128ctr(seed, self.__p1_sz + self.__p2_sz)
        return (pk[0:self.__p1_sz], pk[self.__p1_sz:])

    """
    Расширение seed секретного ключа в матрицу O
    """
    def __expand_sk(self, seed_sk):
        """
        Args:
            seed_sk: seed длиной sk_seed_len бит

        Note:
            Параметры n, m, q используются из self
            q: размер поля (16 или 256)

        Returns:
            Устанавливает self.__O - матрица O размера (n-m) × m
        """
        shake: SHAKE256_XOF = SHAKE256.new(b"{seed_sk:=b}")
        esk = shake.read(32)

        # Используем SHAKE256 для генерации псевдослучайных данных
        # Генерируем матрицу O в column-major порядке
        self.__O = []

    """
    Расширение сжатого публичного ключа в полный
    """
    def __expand_pk(self, pk):
        """
        Args:
            pk: сжатый публичный ключ

        Returns:
            epk: расширенный публичный ключ

        Note:
            Реализует алгоритм UOV.ExpandPK(cpk)
        """
        seed_pk = pk[:self.seed_pk_sz]
        p3 = pk[self.seed_pk_sz:]
        (p1, p2) = self.__expand_p(seed_pk)
        epk = p1 + p2 + p3
        return epk

    # ================================================================
    #                         PUBLIC METHODS
    # ================================================================

    def multiple_over_GF(self, lhs: int, rhs: int) -> int:
        return int(self.__GF(lhs) * self.__GF(rhs))

    """
    Генерация пары ключей для схемы UOV
    """
    def keygen(self):
        """
        Returns:
            tuple: (pk, sk) - пара (публичный и секретный ключи)
        """

        # Генерация seed для секретного ключа
        seed_sk: int = random.getrandbits(self.__sk_seed_bitlen)
        # self.__seed_pk: int = random.getrandbits(self.__pk_seed_bitlen)

        # Генерация seed для публичного ключа и параметра so
        seed_pk_so = self.shake256(seed_sk, self.seed_pk_sz + self.so_sz)
        seed_pk = seed_pk_so[:self.seed_pk_sz]
        so = seed_pk_so[self.seed_pk_sz:]

        # Расширение seed публичного ключа в компоненты P1 и P2
        (p1, p2) = self.expand_p(seed_pk)

        # Вычисление секретного ключа и компонента P3
        (sks, p3) = self.calc_f2_p3(p1, p2, so)

        # Формирование публичного ключа (с учетом сжатия)
        if self.pkc:
            pk = seed_pk + p3                # cpk - сжатый публичный ключ
        else:
            pk = p1 + p2 + p3                # epk - расширенный публичный ключ

        # Формирование секретного ключа (с учетом сжатия)
        if self.skc:
            sk = seed_sk                     # csk - сжатый секретный ключ
        else:
            sk = seed_sk + so + p1 + sks     # esk - расширенный секретный ключ

        return (pk, sk)