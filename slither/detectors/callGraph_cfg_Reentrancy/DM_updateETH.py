class DM_updateETH():
    def union_dict(d1, d2):
        d3 = {k: d1.get(k, set()) | d2.get(k, set()) for k in set(list(d1.keys()) + list(d2.keys()))}
        return d3