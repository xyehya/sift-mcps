"""Optional external anchoring for DB-derived custody proof material."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)
_MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
_SOLANA_MAINNET_RPC = "https://api.mainnet-beta.solana.com"
_SOLANA_DEVNET_RPC = "https://api.devnet.solana.com"


def anchor_db_proof(*, manifest_version: int, manifest_hash: str, ledger_tip_hash: str, keypair_path: str | None = None, rpc_url: str | None = None, cluster: str = "mainnet") -> dict:
    """Build optional external proof from DB authority without touching case files."""
    mh = manifest_hash.split(":")[-1]
    tip = ledger_tip_hash.split(":")[-1]
    proof = {"schema": "sift.evidence-anchor.v1", "timestamp": datetime.now(timezone.utc).isoformat(), "manifest_version": manifest_version, "manifest_hash": manifest_hash, "ledger_tip_hmac": ledger_tip_hash, "anchor_payload": f"SIFT|{mh[:16]}|{tip[:16]}", "solana_tx": None, "solana_cluster": cluster, "confirmed": False, "explorer_url": None}
    if keypair_path:
        try:
            _do_solana_anchor(proof, keypair_path, rpc_url, cluster)
        except ImportError:
            logger.warning("anchor_db_proof: solders unavailable; proof remains local")
        except Exception as exc:
            logger.warning("anchor_db_proof: Solana submission failed: %s", exc)
    return proof


def _do_solana_anchor(proof: dict, keypair_path: str, rpc_url: str | None, cluster: str) -> None:
    import base64
    import time

    from solders.hash import Hash as SolHash  # type: ignore[reportMissingImports]
    from solders.instruction import (  # type: ignore[reportMissingImports]
        AccountMeta,
        Instruction,
    )
    from solders.keypair import Keypair  # type: ignore[reportMissingImports]
    from solders.message import Message  # type: ignore[reportMissingImports]
    from solders.pubkey import Pubkey  # type: ignore[reportMissingImports]
    from solders.transaction import Transaction  # type: ignore[reportMissingImports]
    rpc = rpc_url or (_SOLANA_MAINNET_RPC if cluster == "mainnet" else _SOLANA_DEVNET_RPC)
    keypair = Keypair.from_bytes(bytes(json.loads(Path(keypair_path).expanduser().read_text())))
    instruction = Instruction(Pubkey.from_string(_MEMO_PROGRAM_ID), proof["anchor_payload"].encode(), [AccountMeta(keypair.pubkey(), True, False)])
    blockhash = SolHash.from_string(_rpc_call(rpc, "getLatestBlockhash", [{"commitment": "finalized"}])["result"]["value"]["blockhash"])
    transaction = Transaction.new_unsigned(Message.new_with_blockhash([instruction], keypair.pubkey(), blockhash))
    transaction.sign([keypair], blockhash)
    response = _rpc_call(rpc, "sendTransaction", [base64.b64encode(bytes(transaction)).decode(), {"encoding": "base64", "skipPreflight": False}])
    if "error" in response:
        raise RuntimeError(f"Solana RPC error: {response['error']}")
    signature = response["result"]
    time.sleep(2)
    proof.update(solana_tx=signature, confirmed=_rpc_call(rpc, "getTransaction", [signature, {"encoding": "json", "commitment": "confirmed"}]).get("result") is not None, explorer_url=(f"https://solscan.io/tx/{signature}" if cluster == "mainnet" else f"https://solscan.io/tx/{signature}?cluster=devnet"))


def _rpc_call(url: str, method: str, params: list) -> dict:
    import urllib.request
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}), timeout=30) as response:
        return json.loads(response.read())
