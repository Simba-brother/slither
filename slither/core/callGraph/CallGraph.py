from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.declarations.function import Function
from slither.core.callGraph.functionNode import FunctionNode
from slither.core.variables.variable import Variable


class CallGraph:
    def __init__(self, slither):
        self.slither = slither
        self._counter_FunctionNodes = 0
        self._FunctionNodes = []
        self.function_Map_node = {}
        self._all_contracts = set()
        self._setFunctionNodes(self.slither.functions)
        self._process_functionNodes(self._FunctionNodes)


    def _setFunctionNodes(self, funcitons):
        for function in funcitons:
            functionNode = FunctionNode(self._counter_FunctionNodes, function)
            functionNode.set_contract(function.contract)
            self._FunctionNodes.append(functionNode)
            self.function_Map_node[function] = functionNode
            self._counter_FunctionNodes += 1
            self._all_contracts.add(function.contract)

    def _process_functionNodes(self, functionNodes):
        for functionNode in functionNodes:
            self._process_functionNode(functionNode)

    def _process_functionNode(self, functionNode):
        for internal_call in functionNode.function.internal_calls:
            self._process_internal_call(functionNode, internal_call)

        for external_call in functionNode.function.high_level_calls:
            self._process_external_call(functionNode, external_call)

    def _process_internal_call(self, functionNode, internal_call):
        if isinstance(internal_call, (Function)):
            if internal_call in self.function_Map_node:
                internal_callNode = self.function_Map_node.get(internal_call)
                self.link_FuncitonNodes(functionNode, internal_callNode)
        elif isinstance(internal_call, (SolidityFunction)):
            if internal_call in self.function_Map_node:
                internal_callNode = self.function_Map_node.get(internal_call)
                self.link_FuncitonNodes(functionNode, internal_callNode)

    def _process_external_call(self, functionNode, external_call):
        external_contract, external_function = external_call

        if not external_contract in self._all_contracts:
            return
        if isinstance(external_function, (Variable)):
            pass
        if external_function in self.function_Map_node:
            external_callNode = self.function_Map_node.get(external_function)
            self.link_FuncitonNodes(functionNode, external_callNode)

    def link_FuncitonNodes(self, n1, n2):
        n1.add_son(n2)
        n2.add_father(n1)

    def test(self, function):
        functionNode = self.function_Map_node.get(function)
        print('函数{}的儿子们 {} 父亲们 {}'.format(function.full_name,
                                                list(node.function.full_name for node in functionNode.sons),
                                                list(node.function.full_name for node in functionNode.fathers)))
