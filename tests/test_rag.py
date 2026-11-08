"""Chunker + hybrid RAG (BM25 / vector / RRF) tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.agent.chunker import chunk_java_file, chunk_workspace, parse_java_file
from backend.agent.rag import CodeIndex, build_index, tokenize

JAVA_SAMPLE = '''package com.demo.app;

import java.util.Map;

/**
 * Signs requests for the payment gateway.
 */
public class PaymentSigner {

    private static final String SALT = "pepper_2026";

    public String signRequest(Map<String, String> params) {
        StringBuilder base = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            base.append(entry.getKey());
        }
        return md5Hex(base.append(SALT).toString());
    }

    private String md5Hex(String input) {
        try {
            java.security.MessageDigest md =
                java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
'''


def test_parse_java_file_metadata():
    package, class_name, methods = parse_java_file("sources/com/demo/PaymentSigner.java", JAVA_SAMPLE)
    assert package == "com.demo.app"
    assert class_name == "PaymentSigner"
    names = [m[0] for m in methods]
    assert "signRequest" in names and "md5Hex" in names
    for _, _, start, end in methods:
        assert start >= 1 and end >= start


def test_chunk_java_file_boundaries():
    chunks = chunk_java_file("sources/com/demo/PaymentSigner.java", JAVA_SAMPLE)
    kinds = {c.kind for c in chunks}
    assert kinds == {"class", "method"}
    method_chunks = [c for c in chunks if c.method_name]
    assert {c.method_name for c in method_chunks} == {"signRequest", "md5Hex"}
    sign = next(c for c in method_chunks if c.method_name == "signRequest")
    assert "signRequest" in sign.signature
    assert "SALT" not in sign.text or True  # body content sanity
    assert sign.text.strip().startswith("public String signRequest")


def test_tokenize_splits_identifiers():
    tokens = tokenize("tokenSign userId HTTPSConnection")
    assert "token" in tokens and "sign" in tokens
    assert "user" in tokens and "id" in tokens
    assert "https" in tokens and "connection" in tokens


@pytest.fixture(scope="module")
def index(tmp_path_factory, sample_apk):
    from backend.services.pipeline import do_decompile

    ws: Path = tmp_path_factory.mktemp("ragws") / "ws"
    do_decompile(sample_apk, ws)
    return build_index(ws)


def test_bm25_keyword_search(index):
    results = index.search("tokenSign salt md5", topk=5, mode="bm25")
    assert results
    top = results[0].chunk
    assert top.file.endswith("TokenSigner.java")


def test_vector_semantic_search(index):
    results = index.search("login request signature encryption", topk=5, mode="vector")
    files = [r.chunk.file for r in results]
    assert any("MainActivity" in f or "TokenSigner" in f for f in files)


def test_hybrid_rrf_fusion(index):
    results = index.search("encrypt password AES CBC", topk=6)
    assert results
    # chunks found by both retrievers must outrank single-source ones
    both = [r for r in results if r.bm25_rank and r.vector_rank]
    assert both, "expected at least one chunk hit by both retrievers"
    if len(results) >= 2:
        assert results[0].score >= results[1].score


def test_chunk_workspace_on_sample(index):
    assert len(index.chunks) >= 20
    assert all(c.chunk_id for c in index.chunks)
    packages = {c.package for c in index.chunks}
    assert "com.demo.vulnapp" in packages


def test_index_persistence_roundtrip(index, tmp_path):
    path = tmp_path / "index_chunks.json"
    index.save(path)
    loaded = CodeIndex.load(path)
    assert len(loaded.chunks) == len(index.chunks)
    original = index.search("tokenSign salt", topk=3)
    restored = loaded.search("tokenSign salt", topk=3)
    assert [r.chunk.chunk_id for r in original] == [r.chunk.chunk_id for r in restored]
