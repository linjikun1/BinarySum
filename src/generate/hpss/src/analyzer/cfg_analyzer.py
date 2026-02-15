import networkx as nx
from itertools import islice

class BinaryCFGAnalyzer:
    def __init__(self):
        self.G = nx.DiGraph()  # Control Flow Graph
        self.entry = None       # Entry basic block address
        self.exit_blocks = set()  # Exit basic block addresses

    def build_cfg_from_json(self, func_cfg):
        """
        Build CFG: Nodes are basic block start addresses, edges are successor relationships.
        """
        for addr_str, block in func_cfg.items():
            addr = int(addr_str)  # Use address as node identifier
            self.G.add_node(addr)
            # Add edges for successors
            for succ in block.get("successors", []):
                self.G.add_edge(addr, succ, weight=1)

        possible_entries = [n for n in self.G.nodes if self.G.in_degree(n) == 0]
        self.entry = min(possible_entries) if possible_entries else (min(self.G.nodes) if self.G.nodes else None)
        self.exit_blocks = {node for node in self.G.nodes if self.G.out_degree(node) == 0}

    def k_shortest_paths(self, source, target, k=3):
        """
        Get k shortest paths from source to target.
        """
        try:
            return list(islice(nx.shortest_simple_paths(self.G, source, target), k))
        except nx.NetworkXNoPath:
            return []

    def is_strictly_connected(self, path):
        """
        Ensure every two consecutive blocks in the path are strictly connected in CFG.
        """
        for i in range(len(path) - 1):
            if path[i + 1] not in self.G.neighbors(path[i]):
                return False
        return True

    def extract_paths(self):
        """
        Extract representative paths (max 3).
        Strategy:
        1. Shortest path
        2. Path covering most new nodes
        3. Another path covering most remaining nodes
        """
        if not self.entry or not self.exit_blocks:
            return [], 0.0
            
        all_paths = []

        # path1: Shortest path
        path1 = []
        min_len = float('inf')
        for target in self.exit_blocks:
            if nx.has_path(self.G, self.entry, target):
                try:
                    path = nx.dijkstra_path(self.G, self.entry, target)
                    if len(path) < min_len and self.is_strictly_connected(path):
                        path1 = path
                        min_len = len(path)
                except nx.NetworkXNoPath:
                    continue
        
        if path1:
            all_paths.append(path1)

        # path2: Cover most new nodes
        uncovered_nodes = set(self.G.nodes) - set(path1)
        coverage = -1
        path2 = []
        
        for target in self.exit_blocks:
            if nx.has_path(self.G, self.entry, target):
                for path in self.k_shortest_paths(self.entry, target, 10):
                    if self.is_strictly_connected(path):
                        overlap = len(set(path) & uncovered_nodes)
                        if overlap > coverage:
                            path2 = path
                            coverage = overlap
        
        if path2:
            all_paths.append(path2)
            uncovered_nodes -= set(path2)

        # path3: Cover remaining nodes
        coverage = -1
        path3 = []
        for target in self.exit_blocks:
            if nx.has_path(self.G, self.entry, target):
                for path in self.k_shortest_paths(self.entry, target, 10):
                    if self.is_strictly_connected(path):
                        overlap = len(set(path) & uncovered_nodes)
                        if overlap > coverage:
                            path3 = path
                            coverage = overlap
        
        if path3:
            all_paths.append(path3)
            uncovered_nodes -= set(path3)

        coverage_ratio = 1 - len(uncovered_nodes) / len(self.G.nodes) if self.G.nodes else 0
        
        unique_paths = [list(p) for p in set(tuple(p) for p in all_paths)]
        return unique_paths, coverage_ratio
