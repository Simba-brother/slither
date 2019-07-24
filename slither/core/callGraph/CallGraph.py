from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.declarations.function import Function
from slither.core.callGraph.functionNode import FunctionNode
from slither.core.variables.variable import Variable
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph


class CallGraph:
    def __init__(self, slither):
        self.slither = slither
        self._counter_FunctionNodes = 0
        self._FunctionNodes = []
        self.function_Map_node = {}
        self._all_contracts = set()
        self._taintFunctionNodes = []
        self._adjoin = []
        self._setFunctionNodes(self.slither.functions)
        self._process_functionNodes(self._FunctionNodes)
        self.addIndirectTaintFunctionNodes(self._FunctionNodes)

    def addIndirectTaintFunctionNodes(self, allFunctionNodes):
        '''

        :param allFunctionNodes:
        :return:
        解决一些functionNode不是直接可以判断为taintFunctionNode,但却间接的调用了那些直观的taintFunctionNode
        '''
        node_num = len(allFunctionNodes)
        myGraph = MyGraph(node_num)
        possibleCleanfunctionNodes = list(set(allFunctionNodes) - set(self._taintFunctionNodes))    # 全部节点 - 直接taint节点
        for possibleCleanfunctionNode in possibleCleanfunctionNodes:
            for taintFunctionNode in self._taintFunctionNodes:
                if taintFunctionNode is possibleCleanfunctionNode:
                    continue
                possibleCleanfunctionNodeToTaintFuncitonNodeList = []
                possibleCleanfunctionNodeToTaintFuncitonNodeList.append(possibleCleanfunctionNode)
                pilotProcessNodes = set(allFunctionNodes) - set([possibleCleanfunctionNode, taintFunctionNode])
                possibleCleanfunctionNodeToTaintFuncitonNodeList.extend(list(pilotProcessNodes))
                possibleCleanfunctionNodeToTaintFuncitonNodeList.append(taintFunctionNode)

                for functionNode in possibleCleanfunctionNodeToTaintFuncitonNodeList[0:node_num - 1]:  # index 范围【0:node_num-2】, 不去管终点的sons
                    for son in functionNode.sons:
                        myGraph.addEdge(possibleCleanfunctionNodeToTaintFuncitonNodeList.index(functionNode) + 1,
                                      possibleCleanfunctionNodeToTaintFuncitonNodeList.index(son) + 1)  # 在构建邻接矩阵的时候要注意index+1!!
                allPaths = myGraph.findAllPathBetweenTwoNodes(possibleCleanfunctionNodeToTaintFuncitonNodeList.index(possibleCleanfunctionNode) + 1,
                                                            possibleCleanfunctionNodeToTaintFuncitonNodeList.index(taintFunctionNode) + 1)
                for path in allPaths:
                    care_callee_FunctionNode = possibleCleanfunctionNodeToTaintFuncitonNodeList[path[-2]-1]
                    for node in possibleCleanfunctionNode.function.nodes:
                        internal_calls = node.internal_calls
                        external_calls = []
                        for external_call in node.high_level_calls:
                            external_contract, external_function = external_call
                            external_calls.append(external_function)

                        for call in set(internal_calls + external_calls):
                            if isinstance(call, Function):
                                if call == care_callee_FunctionNode.function:
                                    possibleCleanfunctionNode.function.taintNodes.append(node)
                                    possibleCleanfunctionNode.setTaint(True)
                                    self._taintFunctionNodes.append(possibleCleanfunctionNode)
                # type list of list


    def _setFunctionNodes(self, funcitons):
        for function in funcitons:
            taintFlag = False
            for node in function.nodes:
                if node.high_level_calls or node.low_level_calls:
                    for ir in node.irs:
                        if hasattr(ir, 'destination'):
                            result = is_tainted(ir.destination, node.function.contract)
                            if result == True:
                                taintFlag = True
                                break
                    if taintFlag:
                        break
            functionNode = FunctionNode(self._counter_FunctionNodes, function)
            functionNode.set_contract(function.contract)
            functionNode.setTaint(taintFlag)
            if taintFlag == True:
                self._taintFunctionNodes.append(functionNode)
            self._FunctionNodes.append(functionNode)
            self.function_Map_node[function] = functionNode
            self._counter_FunctionNodes += 1
            self._all_contracts.add(function.contract)

    @property
    def functionNodes(self):
        return self._FunctionNodes

    @property
    def taintFunctionNodes(self):
        return self._taintFunctionNodes

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

    def set_adjoin(self):   # 设置临街矩阵
        for functionNode in self._FunctionNodes:
            for son in functionNode.sons:
                self._adjoin.append(set([functionNode, son]))
    @property
    def adjoin(self):
        return self._adjoin

    def test(self, function):
        functionNode = self.function_Map_node.get(function)
        print('函数{}的儿子们 {} 父亲们 {}'.format(function.full_name,
                                                list(node.function.full_name for node in functionNode.sons),
                                                list(node.function.full_name for node in functionNode.fathers)))
