import galois
import numpy as np
from sympy import Matrix, solve, symbols
from UOV import uov  # импортируем все функции из основной реализации

from test_solve_ls import solve as XL_solve, solve_equat

# Используем те же параметры, что и в основной реализации

def PRINT_LINSYS(equations, unknown_variables):
    # with open("matr.txt", "w") as f:
    #     f.write(equations)

    # import io
    # outFile = io.open('matr.txt', 'w', encoding='utf8')
    # outFile.write(equations)
    # outFile.close()

    # print("\n[+] WRITE DONE\n")
    
    print(equations)




"""
    В UOV секретный ключ состоит из двух частей: центральных полиномов F^(k) и матрицы преобразования T.
    Открытый ключ получается как P^(k) = T^T · F^(k) · T.
    Атака пытается "отменить" это преобразование пошагово.
"""
class UOVReconciliationAttack(uov):
    """
    Класс для реализации атаки reconciliation на схему UOV с использованием XL-метода.
    """

    # =========== ИНИЦИАЛИЗАЦИЯ ===========
    def __init__(self, public_key, n: int, m:int, q: int):
        """
        Инициализация атаки

        Args:
            public_key: открытый ключ UOV (список матриц или expanded public key)
            n: общее количество переменных(масляные+уксусные)
            m: количество полиномов(количество равно количество масляных переменных)
        """
        self.__n  = n
        self.__m  = m       # это 'o' в алгоритме
        self.__v  = n - m   # количество vinegar переменных
        self.__q  = q
        self.__GF = galois.GF(self.__q)

        self.public_polynomials = []
        if isinstance(public_key, tuple):
            # Если передан компактный ключ, расширяем его
            self.public_polynomials = self.__expand_pk(public_key)
        else:
            # Если уже расширенный ключ
            self.public_polynomials += public_key

        print(f"Инициализирована атака: n={self.__n}, m={self.__m}, v={self.__v}")

    """
    ....................................................
    ............... ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ .............
    ....................................................
    """

    # ---------- Создание tшек для _build_quadratic_system ----------
    def _create_unknown_variables_t(self, current_j):
        """
        Создать неизвестные переменные для матрицы преобразования T_{j+1}
        Args:
            current_j: текущий индекс переменной
        Returns:
            T_matr: символьная матрица T_{j+1}
            unknown_variables: список неизвестных переменных
        """
        # Создаем единичную матрицу размера n×n
        T_matr = Matrix.eye(self.__n)

        # Создаем неизвестные переменные только для vinegar элементов
        unknown_variables = []
        # unknown_variables = self.__GF.Zeros(self.__v)

        # В столбце current_j первые v элементов - неизвестные
        for vinegar_row in range(self.__v):
            # variable_name = f't_{vinegar_row}_{current_j}'
            variable_name = f'x_{vinegar_row}'
            unknown_variable = symbols(variable_name)
            T_matr[vinegar_row, current_j] = unknown_variable
            unknown_variables.append(unknown_variable)
            # unknown_variables[vinegar_row] = unknown_variable

        return T_matr, unknown_variables

    # ---------- Расширение системы уравнений для _solve_with_xl ----------
    def _xl_expand_system(self, equations, variables, max_degree):
        """
        Расширить систему уравнений по методу XL
        Args:
            equations: исходные уравнения
            variables: переменные
            max_degree: максимальная степень
        Returns:
            extended_equations: расширенная система
        """
        from itertools import combinations_with_replacement

        extended_equations = list(equations)  # начинаем с исходных уравнений

        # Генерируем мономы до степени max_degree
        for degree in range(2, max_degree + 1):
            print(f"Добавляем уравнения степени {degree}")

            # Генерируем все мономы данной степени
            for monomial_vars in combinations_with_replacement(variables, degree - 2):
                if not monomial_vars:  # пустой моном
                    continue

                # Умножаем каждое исходное уравнение на этот моном
                monomial = 1
                for var in monomial_vars:
                    monomial *= var

                for eq in equations:
                    extended_eq = eq * monomial
                    extended_equations.append(extended_eq)

        return extended_equations

    # ---------- Обновление полиномов для reconciliation_attack_xl ----------
    def _update_polynomials(self, polynomials, T_matr):
        """
        Обновить полиномы: P_j = T^T * P_{j+1} * T
        Args:
            polynomials: текущий список полиномов
            T_matr: матрица преобразования
        Returns:
            updated: обновленный список полиномов
        """
        updated = []    # Список для обновленных полиномов
        T_T = T_matr.T  # Транспонируем матрицу T

        # Обновляем каждый полином P_j
        for P in polynomials:
            P_new = T_T @ P @ T_matr
            updated.append(P_new)

        return updated

    # ---------- Вычисление общей матрицы преобразования ----------
    def _compute_total_transformation(self, T_matrices):
        """
        Вычислить общую матрицу преобразования
        Args:
            T_matrices: список матриц преобразования
        Returns:
            M_T: итоговая матрица преобразования
        """
        if not T_matrices:
            return self.__GF.Identity(self.__n) # Если нет матриц, возвращаем единичную матрицу

        M_T = T_matrices[0] #M_T - первая матрица преобразования
        for T in T_matrices[1:]:
            M_T = M_T @ T   # Умножаем последовательно все матрицы T с использованием библиотеки galois

        return M_T

    def _gauss_solve(self, A, b):
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

    """
    .............................................
    ............... ОСНОВНЫЕ МЕТОДЫ .............
    .............................................
    """

    # =========== ПОСТРОЕНИЕ СИСТЕМЫ КВАДРАТИЧНЫХ УРАВНЕНИЙ ===========
    def _build_quadratic_system(self, current_polynomials, current_j):
        """
        Построить систему квадратичных уравнений (шаги 2-4) вида
            f₁(t₁, t₂, ..., tᵥ) = 0
            f₂(t₁, t₂, ..., tᵥ) = 0
            ...
            fₘ₍ₙ₋ⱼ₎(t₁, t₂, ..., tᵥ) = 0
        Args:
            current_polynomials: текущий список матриц полиномов P_{j+1}^{(k)}
            current_j: индекс текущей переменной
        Returns:
            quadratic_equations: список квадратичных уравнений
            vinegar_variables: символьные переменные для решения
        """
        print(f"Строим систему для j={current_j}")

        """
                Шаг 2: Создаем матрицу T_{j+1} специального вида

                T' = [1  0 | t₁₃  t₁₄] = [I_{v×v}  T'_{v×o}]
                     [0  1 | t₂₃  t₂₄]   [0_{o×v}  I_{o×o}]
                     [----+----------] 
                     [0  0 |  1    0 ]
                     [0  0 |  0    1 ]

                где 
                t₁₃, t₁₄, ..., t₂₃, t₂₄ - это переменные преобразования T_{j+1} для масляных переменных
                I_{v×v} = I_{2×2} = единичная матрица 2×2
                T'{v×o} = T'{2×2} = произвольная матрица 2×2
                0_{o×v} = 0_{2×2} = нулевая матрица 2×2
                I_{o×o} = I_{2×2} = единичная матрица 2×2
                """

        # Создаем матрицу преобразования T_{j+1} правильной формы
        matr_size = current_j + 1
        T_matr, unknown_variables = self._create_unknown_variables_t(current_j)

        quadratic_equations = []
        # quadratic_equations = self.__GF.Zeros(self.__m)
        
        # Для каждого полинома k строим уравнение
        for polynomial_index in range(self.__m):
            polynomial_matr = Matrix(current_polynomials[polynomial_index])

            # Вычисляем U^(k) = T^T * P^(k) * T
            result_matr = T_matr.T * polynomial_matr * T_matr

            # Требуем, чтобы элемент на позиции (j+1, j+1) был равен 0
            zero_constraint_position = current_j    # это индекс j+1 в нумерации с 0, позиция (j+1, j+1) в матрице
            constraint_equation = result_matr[zero_constraint_position, zero_constraint_position]
            quadratic_equations.append(constraint_equation) # добавляем уравнение в список, constraint - это выражение, равное 0
            # quadratic_equations[polynomial_index] = constraint_equation

        return quadratic_equations, unknown_variables

    # =========== РЕШЕНИЕ СИСТЕМЫ УРАВНЕНИЙ (XL) ===========
    def _solve_with_xl(self, equations, unknown_variables, max_degree):
        """
        Решение системы квадратичных уравнений алгоритмом XL
        Args:
            equations: список квадратичных уравнений (sympy выражения)
            unknown_variables: список неизвестных переменных (sympy символы)
            max_degree: максимальная степень для XL
        Returns:
            solution: словарь {переменная: значение} или None
        """
        print(f"Решаем систему из {len(equations)} уравнений с {len(unknown_variables)} неизвестными")
        print(f"XL: максимальная степень = {max_degree}")

        try:
            # Простой подход: пробуем решить систему напрямую
            print("Пробуем решить систему напрямую...")
            # direct_solution = solve(equations, unknown_variables)
            
            # TODO: распечатать систему уравнений
            # direct_solution = self._gauss_solve(equations, unknown_variables)
            # direct_solution = XL_solve(equations, unknown_variables, max_degree)
            direct_solution = solve_equat(equations, unknown_variables)
            
            # PRINT_LINSYS(equations, unknown_variables)
            

            if direct_solution:
                print("Система решена напрямую!")
                return direct_solution

            # Если прямое решение не работает, используем XL подход
            print("Прямое решение не найдено, используем XL расширение...")

            # XL: расширяем систему умножением на мономы
            # extended_equations = self._xl_expand_system(equations, unknown_variables, max_degree)

            # Решаем расширенную систему
            # print(f"Расширенная система: {len(extended_equations)} уравнений")
            # xl_solution = solve(extended_equations, unknown_variables)

            # if xl_solution:
            #     print("Система решена с помощью XL!")
            #     return xl_solution

            print("XL не смог решить систему")
            return None

        except Exception as e:
            print(f"Ошибка при решении системы: {e}")
            return None

    # ---------- ПОСТРОЕНИЕ МАТРИЦЫ ПРЕОБРАЗОВАНИЯ ----------
    def _construct_transformation_matrix(self, solution, current_j):
        """
        Построить матрицу преобразования из решения
        Args:
            solution: найденное решение (словарь переменных)
            current_j: текущий индекс переменной
        Returns:
            T_matrix: матрица преобразования
        """
        T_matr = self.__GF.Identity(self.__n)

        # Применить найденные значения переменных
        for vinegar_row in range(self.__v):
            variable_name = f't_{vinegar_row}_{current_j}'
            if variable_name in solution:
                value = int(solution[variable_name]) % 256
                T_matr[vinegar_row, current_j] = self.__GF(value)

        return T_matr

    # ---------- ОСНОВНОЙ МЕТОД АТАКИ ----------
    def reconciliation_attack_xl(self, max_xl_degree=3):
        """
        Основная функция атаки UOV-reconciliation с XL

        Args:
            max_xl_degree: максимальная степень для XL алгоритма

        Returns:
            tuple: (F_polynomials, transformation_matrix) или None если неудача
        """
        print("Начинаем UOV reconciliation attack с XL...")

        # Копируем текущие полиномы
        P_current = [P.copy() for P in self.public_polynomials]
        T_matrices = []

        # Основной цикл (шаги 1-7)
        for j in range(self.__n - 1, self.__v - 1, -1):
            print(f"\n--- Шаг {self.__n - j}: обрабатываем позицию j = {j} ---")

            # try:
            # Шаг 2-4: Построить систему уравнений
            equations, T_vars = self._build_quadratic_system(P_current, j)
            print(f"Построена система из {len(equations)} уравнений")

            # Шаг 5: Решить с помощью XL
            print("Решаем систему с XL...")
            
            solution = self._solve_with_xl(equations, T_vars, max_xl_degree)
                       

            if solution is None:
                print(f"Не удалось решить систему на шаге j={j}")
                return None

            # Применить решение
            T_j_plus_1 = self._construct_transformation_matrix(solution, j)
            T_matrices.append(T_j_plus_1)

            # Шаг 6: Обновить полиномы
            P_current = self._update_polynomials(P_current, T_j_plus_1)
            print(f"Полиномы обновлены для j={j}")

            # except Exception as e:
            #     print(f"Ошибка на шаге j={j}: {e}")
            #     return None

        # Шаги 8-10: Финализация
        print("\nФинализация атаки...")
        M_T = self._compute_total_transformation(T_matrices)
        F_polynomials = P_current

        print("Атака завершена успешно!")
        return F_polynomials, M_T

"""
--------------------------------------------------
---------------ТЕСТИРОВАНИЕ АТАКИ-----------------
--------------------------------------------------
"""


# if __name__ == "__main__":
#     # Точка входа для запуска теста атаки
#     test_attack()