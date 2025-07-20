"""
XL-alg
1: for i = 1 to n do
2:
  Fix an integer D > 2.
3:
  Let T^(D−2) be the set of all monomials up to degree (D − 2) and define P̃D to be the set of
  all polynomials of the form hp^(j) with h ∈ T^(D−2) and j = 1, ..., m.
4:
  Let >σ be a monomial ordering according to which the univariate polynomials in xi and
  the constant terms come last. Sort the monomials of P̃D according to >σ and interpret each
  monomial as an independent variable. Perform Gaussian elimination on the resulting system.
  If this produces a univariate polynomial p̂(xi ), go to the next step. Otherwise, choose a larger
  value for D and try again.
5:
  Use Berlekamp’s algorithm to find the value x̄i of xi and substitute this value into the
  polynomials of P .
6: end for
7: return x̄ = (x̄1 , . . . , x̄n ).

"""

import galois
import numpy as np
from UOV import uov  # Импорт функций из основной реализации
from itertools import product, combinations_with_replacement

# Используем те же параметры, что и в основной реализации
# GF256 = galois.GF(256)

class UOVReconciliationAttack(uov):
    def __init__(self, public_key, n, m, q):
        self.__n = n
        self.__m = m  # Количество масляных переменных
        self.__v = n - m  # Количество уксусных переменных
        self.__q = q

        self.__GF = galois.GF(self.__q)
        if isinstance(public_key, tuple):
            self.public_polynomials = self.__expand_pk(public_key)
        else:
            self.public_polynomials = public_key

        print(f"Инициализирована атака: n={n}, m={m}, v={self.__v}")

    def _create_unknown_variables_t(self, current_j):
        T_matr = self.__GF.Identity(self.__n)
        # В столбце current_j первые v элементов будут неизвестными
        return T_matr, self.__v

    def _build_quadratic_system(self, current_polynomials, current_j):
        print(f"Строим систему для j={current_j}")
        equations = []
        constants = []
        
        # Для каждого полинома в открытом ключе
        for P in current_polynomials:
            # Извлекаем подматрицу для уксусных переменных (v x v)
            A = P[:self.__v, :self.__v]
            # Константа из диагонального элемента
            c = P[current_j, current_j]
            equations.append(A)
            constants.append(c)
            
        return equations, constants

    def _solve_quadratic_system(self, equations, constants, max_degree=3):
        print("\t[!] Start '_solve_quadratic_system'")
        v = self.__v
        print(self.__v)
        print(f"Решаем систему из {len(equations)} уравнений с {v} неизвестными")
        
        # Генерация всех мономов степени <= max_degree
        monomials = []
        for deg in range(max_degree + 1):
            # for exp in product(range(deg + 1), repeat=v):
            for exp in product(range(deg + 1)):
                if sum(exp) <= deg:
                    monomials.append(tuple(exp))
                    # print(monomials)
        
        # Создаем матрицу коэффициентов
        num_monomials = len(monomials)
        num_equations = len(equations)
        M = self.__GF.Zeros((num_equations, num_monomials))
        
        # Заполняем матрицу коэффициентов
        for eq_idx, (A, c) in enumerate(zip(equations, constants)):
            for mono_idx, exp in enumerate(monomials):
                coeff = self.__GF(0)
                # Константный член
                if sum(exp) == 0:
                    coeff = c
                # Квадратичные члены
                elif sum(exp) == 2:
                    # Находим индексы ненулевых степеней
                    idxs = [i for i, e in enumerate(exp) if e > 0]
                    if len(idxs) == 1:  # Случай t_i^2
                        i = idxs[0]
                        coeff = A[i, i]
                    else:  # Случай t_i t_j
                        i, j = idxs
                        coeff = A[i, j]
                M[eq_idx, mono_idx] = coeff
        
        # Решение системы с помощью SVD
        U, S, Vt = np.linalg.svd(M, full_matrices=False)
        # Ищем вектор в ядре
        # kernel = Vt[-1]
        kernel = np.array(Vt[-1], dtype=float)
        
        # Извлекаем решение для переменных
        print(monomials)
        solution = {}
        for i in range(v):
            # Моном, соответствующий переменной t_i
            mono = tuple(1 if j == i else 0 for j in range(1))
            # mono = tuple(1 if j == i else 0)
            idx = monomials.index(mono)
            name: str= f't_{i}_{self.__v}'
            solution[name] = int(kernel[idx])
        
        return solution

    def _update_polynomials(self, polynomials, T_matr):
        updated = []
        T_T = T_matr.T  # Транспонирование матрицы
        for P in polynomials:
            P_new = T_T @ P @ T_matr
            updated.append(P_new)
        return updated

    def _compute_total_transformation(self, T_matrices):
        if not T_matrices:
            return self.__GF.Identity(self.__n)
        M_T = T_matrices[0]
        for T in T_matrices[1:]:
            M_T = M_T @ T
        return M_T


    def reconciliation_attack_xl(self, max_xl_degree=3):
        print("Начинаем UOV reconciliation attack с XL...")
        print(f"Параметры: n={self.__n}, m={self.__m}, v={self.__v}")
        
        P_current = [P.copy() for P in self.public_polynomials]
        T_matrices = []
        
        for j in range(self.__n - 1, self.__v - 1, -1):
            print(f"\n--- Шаг {self.__n - j}: обрабатываем позицию j = {j} ---")
            try:
                # Построение системы уравнений
                eqs, consts = self._build_quadratic_system(P_current, j)
                solution = self._solve_quadratic_system(eqs, consts, max_xl_degree)
                # solution = gauss_elimination()
                
                if not solution:
                    print(f"Не удалось решить систему на шаге j={j}")
                    return None
                
                # Построение матрицы преобразования                
                T_j = self.__GF.Identity(self.__n)
                for i in range(self.__v):
                    var_name = f't_{i}_{self.__v}'
                    T_j[i, j] = solution[var_name]
                
                T_matrices.append(T_j)
                print(f"Построена матрица преобразования T_{j + 1}")
                
                # Обновление полиномов
                P_current = self._update_polynomials(P_current, T_j)
                print(f"Полиномы обновлены для j={j}")
                
            except Exception as e:
                print(f"Ошибка на шаге j={j}: {e}")
                import traceback
                traceback.print_exc()
                return None
        
        print("\nФинализация атаки...")
        M_T = self._compute_total_transformation(T_matrices)
        F_polynomials = P_current
        
        print("Атака завершена успешно!")
        return F_polynomials, M_T


def test_attack():
    print("=== Тест UOV reconciliation attack ===")
    from uovtop import n, m
    
    # Генерация тестовых ключей
    print("Генерируем тестовые ключи...")
    cpk, csk = generate_keypair()
    epk = expand_pk(cpk)
    print(f"Ключи созданы. Размер открытого ключа: {len(epk)} полиномов")
    
    # Создание объекта атаки
    attack = UOVReconciliationAttack(epk, n, m)
    result = attack.reconciliation_attack_xl(max_xl_degree=3)
    
    if result is not None:
        F_recovered, M_T = result
        print("Атака завершена успешно!")
        print(f"Восстановлено {len(F_recovered)} полиномов")
        print(f"Размер матрицы преобразования: {M_T.shape}")
    else:
        print("Атака не удалась")

if __name__ == "__main__":
    test_attack()
