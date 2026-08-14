#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Hard benign sample: eval for math expression evaluation
# Business: online calculator, eval runs in restricted namespace.
# Safe: __builtins__ disabled, regex+AST whitelist, no underscores.

import ast, math, re, time

class SafeMathEvaluator:
    """Safe math expression evaluator"""

    FUNCS = {'sin': math.sin, 'cos': math.cos, 'sqrt': math.sqrt,
             'log': math.log, 'abs': abs, 'max': max, 'min': min}
    CONSTS = {'pi': math.pi, 'e': math.e}
    NODES = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num,
             ast.Constant, ast.Name, ast.Load, ast.Call, ast.keyword)
    BINOPS = {ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow}
    UNOPS = {ast.UAdd, ast.USub}

    def __init__(self):
        self._g = {"__builtins__": {}}
        self._l = {**self.FUNCS, **self.CONSTS}

    def _check(self, expr):
        """Regex whitelist + AST validation"""
        if len(expr) > 200:
            raise ValueError("too long")
        idents = set(re.findall(r'[a-zA-Z_]\w*', expr))
        for i in idents:  # reject underscores
            if '_' in i:
                raise ValueError(f"not allowed: {i}")
        ok = set(self.FUNCS) | set(self.CONSTS)
        if idents - ok:
            raise ValueError(f"unknown: {', '.join(idents - ok)}")
        if not re.match(r'^[0-9+\-*/().,\s a-zA-Z]+$', expr):
            raise ValueError("invalid char")

    def _ast_check(self, node):
        """AST node type whitelist"""
        if not isinstance(node, self.NODES):
            raise ValueError(f"bad: {type(node).__name__}")
        if isinstance(node, ast.BinOp) and type(node.op) not in self.BINOPS:
            raise ValueError("bad op")
        if isinstance(node, ast.UnaryOp) and type(node.op) not in self.UNOPS:
            raise ValueError("bad unary")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in self.FUNCS:
                raise ValueError("bad call")
        if isinstance(node, ast.Name) and node.id not in set(self.FUNCS) | set(self.CONSTS):
            raise ValueError(f"bad name: {node.id}")
        for c in ast.iter_child_nodes(node):
            self._ast_check(c)

    def evaluate(self, expression):
        """Safe eval of math expression"""
        if not isinstance(expression, str) or not expression.strip():
            raise ValueError("empty")
        expr = expression.strip()
        self._check(expr)
        try:
            tree = ast.parse(expr, mode='eval')
        except SyntaxError as e:
            raise ValueError(f"syntax: {e}")
        self._ast_check(tree)
        # eval in restricted namespace
        t = time.time()
        try:
            r = eval(compile(tree, '<e>', 'eval'), self._g, self._l)
        except Exception as e:
            raise ValueError(f"err: {e}")
        if time.time() - t > 1.0:
            raise ValueError("timeout")
        if not isinstance(r, (int, float)):
            raise ValueError("bad type")
        return r
