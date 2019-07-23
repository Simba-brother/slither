from slither.detectors.callGraph_cfg_Reentrancy.Graph import MyGraph
def test():
    graph = MyGraph(12)
    lian = [[0, 1], [1, 2], [1, 3], [1, 4], [2, 5], [2, 6], [3, 11], [4, 11], [5, 7], [5, 8], [6, 9], [6, 10], [7, 11], [8, 11], [9, 11]]
    for item in lian:
        graph.addEdge(item[0]+1, item[1]+1)
    for gitem in graph.adjMat():
        print(gitem)

    graph.findAllPathBetweenTwoNodes(1, 12)
    # a = [[0] * 3for i in range(4)]
    # print(a)
    # print(set([1,3]))
    # a = set()
    # a.add(4)
    # a.add(5)
    # print(a)
test()


def test2():
    index = 0
    for i in range(1, 5):
        index = i
    print(index)
# test2()
