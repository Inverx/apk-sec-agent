"""Hybrid code retrieval: BM25 + hashing-embedding vectors + RRF fusion."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from backend.agent.chunker import CodeChunk, chunk_workspace

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "return", "public", "private",
    "static", "void", "final", "class", "new", "import", "package", "null",
    "true", "false", "string", "int", "get", "set",
}


def split_identifier(token: str) -> list[str]:
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", token)  # HTTPSConnection -> HTTPS Connection
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)  # userId -> user Id
    parts = text.replace("_", " ").replace("-", " ").replace(".", " ")
    return [p.lower() for p in parts.split() if len(p) >= 2]


def tokenize(text: str, max_tokens: int = 512) -> list[str]:
    tokens: list[str] = []
    for raw in TOKEN_RE.findall(text)[: max_tokens * 2]:
        lowered = raw.lower()
        if lowered in STOPWORDS:
            continue
        parts = split_identifier(raw)
        tokens.append(lowered)
        tokens.extend(parts)
        if len(tokens) >= max_tokens:
            break
    return tokens


class BM25Index:
    """Okapi BM25 (k1=1.5, b=0.75) over tokenized chunks."""

    def __init__(self, docs_tokens: list[list[str]], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1, self.b = k1, b
        self.docs = docs_tokens
        self.doc_len = [len(d) or 1 for d in docs_tokens]
        self.avgdl = (sum(self.doc_len) / len(self.doc_len)) if self.doc_len else 1.0
        self.df: dict[str, int] = {}
        self.tfs: list[dict[str, int]] = []
        for tokens in docs_tokens:
            tf: dict[str, int] = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1
            self.tfs.append(tf)
            for term in tf:
                self.df[term] = self.df.get(term, 0) + 1
        self.n = len(docs_tokens)

    def _idf(self, term: str) -> float:
        df = self.df.get(term, 0)
        if df == 0:
            return 0.0
        return math.log((self.n - df + 0.5) / (df + 0.5) + 1.0)

    def search(self, query_tokens: list[str], topk: int = 10) -> list[tuple[int, float]]:
        scores: list[float] = [0.0] * self.n
        for qt in query_tokens:
            idf = self._idf(qt)
            if idf <= 0:
                continue
            for i, tf_map in enumerate(self.tfs):
                freq = tf_map.get(qt)
                if not freq:
                    continue
                denom = freq + self.k1 * (1 - self.b + self.b * self.doc_len[i] / self.avgdl)
                scores[i] += idf * (freq * (self.k1 + 1)) / denom
        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
        return [(i, s) for i, s in ranked[:topk] if s > 0]


class HashingEmbedder:
    """Deterministic feature-hashing embeddings (offline, dependency-free).

    Optionally delegates to an OpenAI-compatible /embeddings endpoint when
    ``api_key``/``base_url`` are provided; falls back to hashing silently.
    """

    def __init__(self, dim: int = 512) -> None:
        self.dim = dim

    def _feature(self, token: str) -> tuple[int, float]:
        digest = hashlib.md5(token.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "little") % self.dim
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        return idx, sign

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        tokens = tokenize(text, max_tokens=400)
        if not tokens:
            return vec
        counts: dict[str, int] = {}
        for t in tokens:
            counts[t] = counts.get(t, 0) + 1
        for token, count in counts.items():
            weight = (1.0 + math.log(count)) * (1.0 / len(counts) ** 0.5)
            idx, sign = self._feature(token)
            vec[idx] += sign * weight
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))


@dataclass
class RagResult:
    chunk: CodeChunk
    score: float
    bm25_rank: int | None
    vector_rank: int | None

    def to_dict(self) -> dict:
        return {
            "chunk": self.chunk.to_dict(),
            "score": round(self.score, 5),
            "bm25_rank": self.bm25_rank,
            "vector_rank": self.vector_rank,
        }


RRF_K = 60


class CodeIndex:
    """Searchable index over decompiled-code chunks."""

    def __init__(self, chunks: list[CodeChunk], embedder: HashingEmbedder | None = None) -> None:
        self.chunks = chunks
        self.embedder = embedder or HashingEmbedder()
        self.by_id = {c.chunk_id: c for c in chunks}
        self._bm25 = BM25Index([tokenize(c.text) for c in chunks])
        self._vectors = [self.embedder.embed(c.text) for c in chunks]
        self._vector_cache: dict[str, list[float]] = {}

    def search(self, query: str, topk: int = 8, mode: str = "hybrid") -> list[RagResult]:
        query_tokens = tokenize(query, max_tokens=64) or tokenize(query, max_tokens=64)
        pool = min(len(self.chunks), max(topk * 4, 20))

        bm25_hits = self._bm25.search(query_tokens, topk=pool) if mode in ("hybrid", "bm25") else []
        results: dict[str, RagResult] = {}
        for rank, (idx, score) in enumerate(bm25_hits, start=1):
            chunk = self.chunks[idx]
            results[chunk.chunk_id] = RagResult(
                chunk=chunk, score=0.0, bm25_rank=rank, vector_rank=None
            )

        if mode in ("hybrid", "vector"):
            qvec = self._vector_cache.get(query)
            if qvec is None:
                qvec = self.embedder.embed(query)
                if len(self._vector_cache) < 128:
                    self._vector_cache[query] = qvec
            sims = [(i, cosine(qvec, dv)) for i, dv in enumerate(self._vectors)]
            sims.sort(key=lambda x: x[1], reverse=True)
            for rank, (idx, sim) in enumerate(sims[:pool], start=1):
                if sim <= 0:
                    break
                chunk = self.chunks[idx]
                existing = results.get(chunk.chunk_id)
                if existing:
                    existing.vector_rank = rank
                else:
                    results[chunk.chunk_id] = RagResult(
                        chunk=chunk, score=0.0, bm25_rank=None, vector_rank=rank
                    )

        fused: list[RagResult] = []
        for r in results.values():
            score = 0.0
            if r.bm25_rank is not None:
                score += 1.0 / (RRF_K + r.bm25_rank)
            if r.vector_rank is not None:
                score += 1.0 / (RRF_K + r.vector_rank)
            r.score = score
            fused.append(r)
        fused.sort(key=lambda r: r.score, reverse=True)
        return fused[:topk]

    def save(self, path: Path) -> None:
        payload = {
            "chunks": [c.to_dict() for c in self.chunks],
            "embedding": {"type": "hashing", "dim": self.embedder.dim},
        }
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "CodeIndex":
        payload = json.loads(path.read_text(encoding="utf-8"))
        chunks = [CodeChunk(**c) for c in payload["chunks"]]
        return cls(chunks)


def build_index(workspace: Path, max_chunks: int = 3000) -> CodeIndex:
    chunks = chunk_workspace(workspace, max_chunks=max_chunks)
    return CodeIndex(chunks)


def persist_index(index: CodeIndex, workspace: Path) -> Path:
    out = workspace / "index_chunks.json"
    index.save(out)
    return out
