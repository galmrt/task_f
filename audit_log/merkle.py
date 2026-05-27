from __future__ import annotations

import hashlib
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def hash_leaf(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def hash_nodes(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode()).hexdigest()


def bag_peaks(peaks: list[str]) -> str:
    """Fold peaks right-to-left: hash(peaks[-2] || hash(peaks[-1]))."""
    result = peaks[-1]
    for peak in reversed(peaks[:-1]):
        result = hashlib.sha256((peak + result).encode()).hexdigest()
    return result


# ---------------------------------------------------------------------------
# MMR
# ---------------------------------------------------------------------------

@dataclass
class Node:
    hash: str
    height: int
    left: int | None = None
    right: int | None = None


@dataclass
class Proof:
    leaf_num: int
    siblings: list[tuple[str, str]]
    other_peaks: list[str]
    peak_list_idx: int


class MMR:
    def __init__(self) -> None:
        self.nodes: list[Node] = []
        self.peaks: list[int] = []
        self.leaf_indices: list[int] = []

    def append(self, leaf_hash: str) -> int:
        """Append a leaf. Returns the index of the first new node (pre-append node count).

        Every node at index >= the returned value is new and should be persisted.
        """
        first_new = len(self.nodes)
        current_idx = first_new
        self.nodes.append(Node(hash=leaf_hash, height=0))
        self.leaf_indices.append(current_idx)

        while (
            len(self.peaks) >= 1
            and self.nodes[self.peaks[-1]].height == self.nodes[current_idx].height
        ):
            left_idx = self.peaks.pop()
            merged = Node(
                hash=hash_nodes(self.nodes[left_idx].hash, self.nodes[current_idx].hash),
                height=self.nodes[left_idx].height + 1,
                left=left_idx,
                right=current_idx,
            )
            current_idx = len(self.nodes)
            self.nodes.append(merged)

        self.peaks.append(current_idx)
        return first_new

    def get_root(self) -> str:
        if not self.peaks:
            raise ValueError("MMR is empty")
        return bag_peaks([self.nodes[i].hash for i in self.peaks])

    def get_proof(self, leaf_num: int) -> Proof:
        if leaf_num < 0 or leaf_num >= len(self.leaf_indices):
            raise IndexError(f"leaf {leaf_num} out of range")

        offset = 0
        peak_list_idx = -1
        leaf_offset = -1
        for i, peak_node_idx in enumerate(self.peaks):
            subtree_leaves = 1 << self.nodes[peak_node_idx].height
            if leaf_num < offset + subtree_leaves:
                peak_list_idx = i
                leaf_offset = leaf_num - offset
                break
            offset += subtree_leaves

        siblings = self._collect_siblings(self.peaks[peak_list_idx], leaf_offset)
        other_peaks = [
            self.nodes[self.peaks[i]].hash
            for i in range(len(self.peaks))
            if i != peak_list_idx
        ]
        return Proof(
            leaf_num=leaf_num,
            siblings=siblings,
            other_peaks=other_peaks,
            peak_list_idx=peak_list_idx,
        )

    def _collect_siblings(self, node_idx: int, leaf_offset: int) -> list[tuple[str, str]]:
        node = self.nodes[node_idx]
        if node.height == 0:
            return []

        left_size = 1 << (node.height - 1)
        if leaf_offset < left_size:
            path = self._collect_siblings(node.left, leaf_offset)
            path.append((self.nodes[node.right].hash, "right"))
        else:
            path = self._collect_siblings(node.right, leaf_offset - left_size)
            path.append((self.nodes[node.left].hash, "left"))
        return path

    @classmethod
    def build(cls, hashes: list[str]) -> MMR:
        if not hashes:
            raise ValueError("cannot build MMR from empty list")
        mmr = cls()
        for h in hashes:
            mmr.append(h)
        return mmr



# ---------------------------------------------------------------------------
# Tamper detection and proof verification
# ---------------------------------------------------------------------------



def verify_proof(leaf_hash: str, proof: Proof, expected_root: str) -> bool:
    """Recompute the MMR root from a leaf + its Merkle proof."""
    current = leaf_hash
    for sibling_hash, side in proof.siblings:
        if side == "right":
            current = hash_nodes(current, sibling_hash)
        else:
            current = hash_nodes(sibling_hash, current)
    all_peaks = (
        proof.other_peaks[: proof.peak_list_idx]
        + [current]
        + proof.other_peaks[proof.peak_list_idx :]
    )
    return bag_peaks(all_peaks) == expected_root
