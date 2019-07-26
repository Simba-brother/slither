from slither.core.cfg.node import NodeType
from slither.core.declarations import Function, SolidityFunction, SolidityVariable
from slither.core.expressions import UnaryOperation, UnaryOperationType
from slither.detectors.abstract_detector import (AbstractDetector,
                                                 DetectorClassification)
from slither.slithir.operations import (HighLevelCall, LowLevelCall,
                                        LibraryCall,
                                        Send, Transfer)
from slither.core.variables.variable import Variable
from slither.detectors.callGraph_cfg_Reentrancy.getAallPaths import getAllPatth
from slither.core.cfg.node import NodeType
from slither.analyses.data_dependency.data_dependency import is_dependent


def allPaths_intToNode(allPathsInt, startToEndNodes):
    allPathsNode = []
    for path in allPathsInt:
        tempPath = []
        for i in path:
            tempPath.append(startToEndNodes[i-1])
    allPathsNode.append(tempPath)
    return allPathsNode


class DM:
    def __init__(self, function):
        self.function = function

    def advancedUpdateEth(self, function):
        allNodes = function.nodes
        for ethNode in function.ethNodes:
            entryPointToethNode = []
            entryPointToethNode.append(function.entry_point)
            pilotProcessNodes = list(set(allNodes) - set([function.entry_point, ethNode]))
            entryPointToethNode.extend(pilotProcessNodes)
            entryPointToethNode.append(ethNode)
            allPaths = getAllPatth(entryPointToethNode)
            allPaths_Node = allPaths_intToNode(allPaths, entryPointToethNode)
            for path in allPaths_Node:
                careifNodeStack = []
                care_if_StateVariablesRead = set()
                care_RequireOrAssert_StateVariableRead = set()
                state_variables_written = set()
                for node in reversed(path):  # [start, end]
                    if node.contains_require_or_assert:
                        care_RequireOrAssert_StateVariableRead |= set(node.state_variables_read)
                    state_variables_written |= set(node.state_variables_written)
                    if node.type == NodeType.IF:
                        careifNodeStack.append(node)
                    if node.type == NodeType.ENDIF:
                        careifNodeStack.pop()
                if careifNodeStack:
                    for careifNode in careifNodeStack:
                        care_if_StateVariablesRead |= set(careifNode.state_variables_read)
                    for stateVariableWritten in state_variables_written:
                        for careStateVariableRead in care_if_StateVariablesRead | care_RequireOrAssert_StateVariableRead:
                            result = is_dependent(stateVariableWritten, careStateVariableRead, function.contract)
                            if result == True:
                                return True

                else:  # 如果 转账语句不在if block中
                    for stateVariableWritten in state_variables_written:
                        for careStateVariableRead in care_RequireOrAssert_StateVariableRead:
                            result = is_dependent(stateVariableWritten, careStateVariableRead, function.contract)
                            if result == True:
                                return True

        return False

    def privateVisibility(self, function):
        if function.visibility == 'private':
            return True
        return False




