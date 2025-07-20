import  numpy       as np
import  galois
from    sympy       import symbols, Poly, simplify, sympify, Eq
from    itertools   import product
import numpy as np


"""
    XL-alg
    1:  for i = 1 to n do
    2:  Fix an integer D > 2.
    3:  Let T^(D−2) be the set of all monomials up to degree (D − 2) and define P̃D to be the set of
        all polynomials of the form hp^(j) with h ∈ T^(D−2) and j = 1, ..., m.
    4:  Let >σ be a monomial ordering according to which the univariate polynomials in xi and
        the constant terms come last. Sort the monomials of P̃D according to >σ and interpret each
        monomial as an independent variable. Perform Gaussian elimination on the resulting system.
        If this produces a univariate polynomial p̂(xi ), go to the next step. Otherwise, choose a larger
        value for D and try again.
    5:  Use Berlekamp’s algorithm to find the value x̄i of xi and substitute this value into the
        polynomials of P .
    6:  end for
    7:  return x̄ = (x̄1 , . . . , x̄n ).
"""

def init_GF_polynoms():
    q = 16
    GF_q = galois.GF(q, repr="poly")
    P = []
    for i in range(q):
        s = str(GF_q(i))
        s = s.replace('α', 'x')
        if len(s) < 2 and s in ['0', '1', 'x']:
            continue
        P.append(s)
    
    # print(P)
    return P


def is_univariate_or_constant(monom, xi_index):
    # Проверяем, что моном содержит только переменную x_i (или константа)
    for i, deg in enumerate(monom):
        if i != xi_index and deg != 0:
            return False
    return True

def monomial_sort_key(monom, xi_index):
    # Унарные по x_i и константы идут в конец (group=1), остальные — впереди (group=0)
    univariate = is_univariate_or_constant(monom, xi_index)
    print("monomial_sort_key [48] : ", univariate)
    group = 1 if univariate else 0
    return (group, monom)

def monom_to_expr(monom, vars):
    expr = 1
    for v, deg in zip(vars, monom):
        expr *= v**deg
    return expr

def get_all_monomials(polys, vars):
    # monoms = set()
    monoms = list()
    for p in polys:
        p_poly = Poly(p, vars)
        # monoms.update(p_poly.monoms())
        if p_poly.monoms() in monoms:
            continue
        monoms.append(p_poly.monoms())
        print(f"{p_poly} : {p_poly.monoms()}")
    return list(monoms)

def build_coefficient_matrix(polys, vars, sorted_monomials):
    n = len(polys)
    m = len(sorted_monomials)
    A = np.zeros((n, m), dtype=object)
    for i, p in enumerate(polys):
        p_poly = Poly(p, vars)
        # coeffs = p_poly.as_dict()
        coeffs = p_poly
        for j, monom in enumerate(sorted_monomials):
            # A[i, j] = coeffs.get(monom, 0)
            A[i, j] = coeffs[0]
    return A

def gaussian_elimination(A):
    A = A.copy()
    n, m = A.shape
    row = 0
    for col in range(m):
        pivot = None
        for r in range(row, n):
            if A[r, col] != 0:
                pivot = r
                break
        if pivot is None:
            continue
        if pivot != row:
            A[[row, pivot]] = A[[pivot, row]]
        pivot_val = A[row, col]
        A[row] = [x / pivot_val for x in A[row]]
        for r in range(n):
            if r != row and A[r, col] != 0:
                factor = A[r, col]
                A[r] = [a - factor*b for a, b in zip(A[r], A[row])]
        row += 1
        if row == n:
            break
    return A

def find_univariate_polynomial(A, sorted_monomials, vars, xi_index):
    n, m = A.shape
    for i in range(n):
        row = A[i]
        # Мономы с ненулевыми коэффициентами в строке
        monoms_in_row = [sorted_monomials[j] for j, c in enumerate(row) if c != 0]
        # Проверяем, все ли мономы унарные по x_i или константы
        if len(monoms_in_row) == 0:
            continue
        if all(is_univariate_or_constant(m, xi_index) for m in monoms_in_row):
            # Формируем полином из коэффициентов и мономов
            poly_expr = sum(c * monom_to_expr(m, vars) for m, c in zip(sorted_monomials, row) if c != 0)
            return simplify(poly_expr)
    return None

# --- Пример использования ---

def solve(polys: list, vars: list, xi_index: int):
    # x= symbols('x')
    
    
    # Пример множества полиномов P̃_D (можно заменить на ваши)
    # polys = [
    #     x**2 + x*y + y**2 - 1,
    #     x*y + y - 0.5
    # ]
    # vars = [x]
    # xi_index = 0  # индекс переменной x_i, например x

    # 1) Собираем все мономы из polys
    all_monomials = get_all_monomials(polys, vars)

    print(all_monomials)

    # 2) Сортируем по правилу >_σ
    sorted_monomials = sorted(all_monomials, key=lambda m: monomial_sort_key(m, xi_index))
    print("sorted_monomials [140] : ", sorted_monomials)
    # 3) Строим матрицу коэффициентов
    A = build_coefficient_matrix(polys, vars, sorted_monomials)

    # 4) Гауссово исключение
    A_reduced = gaussian_elimination(A)

    # 5) Ищем унарный полином по x_i
    uni_poly = find_univariate_polynomial(A_reduced, sorted_monomials, vars, xi_index)

    print("Унарный полином по переменной", vars[xi_index], ":")
    print(uni_poly if uni_poly is not None else "Не найден")
    
    return uni_poly

def solve_equat(P_D: list, vars: list, max_degree: int): 
    # x = symbols('x')
    # expr = sympify("2*x + 3 - 7")  # преобразует строку в символьное выражение
    for el in range(3, len(P_D)):
        print(f"\t[!] {P_D[el]} = 0", end='\t')
        expr = sympify(P_D[el])  # преобразует строку в символьное выражение
        print(expr)
        solution = solve(polys=Eq(expr, 0), vars=vars, xi_index=max_degree)
        print(solution)  # Выведет: [2]
        return solution


def main():
    polys = init_GF_polynoms()
    # polys.pop(0)
    # polys.pop(0)
    # polys.pop(0)
    solve(polys)
    



if __name__ == "__main__":
    main()
