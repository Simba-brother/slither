from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.declarations.function import Function
from slither.core.callGraph.functionNode import FunctionNode
from slither.core.variables.variable import Variable
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph
from slither.detectors.ICFG_Reentrancy.smallUtils import (get_CFGnode_Calls, getCFG_endNodes, link_icfgNodes, link_backIcfgNodes)

import copy


class ICFG:
    def __init__(self, slither):
        self._slither = slither
        self.allNodes = []
        self.visitedList = []
    def build_ICFG(self):
        for function in self._slither.functions:
            if not function.is_implemented:
                continue
            if function in self.visitedList:
                return
            self.visitedList.append(function)
            self.allNodes.extend(function.nodes)
            for node in function.nodes:
                callees = get_CFGnode_Calls(node)
                for callee in callees:
                    #print('被调用函数的名字：{}'.format(callee.full_name))
                    # node.add_icfgSon(callee.entry_point)
                    if callee.entry_point is None:
                        continue
                    link_icfgNodes(node, callee.entry_point)
                    callee_cfgEndNodes = getCFG_endNodes(callee)
                    for callee_cfgEndNode in callee_cfgEndNodes:
                        for cfgSon in node.sons:
                            link_backIcfgNodes(callee_cfgEndNode, cfgSon)


