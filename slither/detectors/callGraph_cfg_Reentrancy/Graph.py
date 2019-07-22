class Graph:
    def __int__(self, node_num):
        self._vertexList = []
        self._adjMat = [[0] * (node_num+1) for i in range(node_num+1)]
        self._node_num = node_num

    def _addEdge(self, node1, node2):
        self._adjMat[node1][node2] = 1

    def _suanfa(self, start, end):
        _is_in_stack = [False] * (self._node_num+1)
        _node_stack = []
        _path = []
        _allPaths = []
        _node_stack.append(start)
        _is_in_stack[0] = True
        top_element = None
        temp = None
        c_position = None
        while _node_stack is not None:
            top_element = _node_stack[-1]
            if top_element == end:
                while _node_stack is not None:
                    temp = _node_stack[-1]
                    _node_stack.pop()
                    _path.append(temp)
                _allPaths.append(_path)
                for item in reversed(_path):
                    _node_stack.append(item)
                _path.clear()  # 清除单条路径
                _node_stack.pop()
                _is_in_stack[top_element] = False
                c_position = _node_stack[-1]
                top_element = _node_stack[-1]
                _node_stack.pop()
                _is_in_stack[top_element] = False
            else:
                for i in range(c_position, self._node_num+2):
                    if _is_in_stack[i] == False and self._adjMat[top_element][i] != 0
