#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional

import requests
from coincurve import PrivateKey

# Configuration 

REST_URL = "https://api.testnet.o2.app"
PROVIDER_URL = "https://testnet.fuel.network/v1/graphql"
OWNER_PRIVATE_KEY = (
    "0x122746c21196c4064426ff3a100b1c7c00a687711ed9fc287bcba5511491c359"
)

# Types 

class OrderType:
    Spot = "Spot"
    Market = "Market"


class OrderSide:
    Buy = "Buy"
    Sell = "Sell"


# Helper Functions 

FUEL_MESSAGE_PREFIX = "\x19Fuel Signed Message:\n"
U64_MAX = 18446744073709551615


def _strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def arrayify(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        # Treat as hex string by default
        hex_str = _strip_0x(value)
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        return bytes.fromhex(hex_str)
    raise TypeError(f"Unsupported type for arrayify: {type(value)}")


def hexlify(value: bytes) -> str:
    return "0x" + value.hex()


def concat(parts: List[Any]) -> bytes:
    return b"".join(arrayify(p) if not isinstance(p, (bytes, bytearray)) else bytes(p) for p in parts)


def to_utf8_bytes(value: str) -> bytes:
    return value.encode("utf-8")


def encode_u64(value: int) -> bytes:
    if value < 0 or value > U64_MAX:
        raise ValueError("u64 out of range")
    return value.to_bytes(8, "big")


def encode_b256(value: str) -> bytes:
    raw = arrayify(value)
    if len(raw) != 32:
        raise ValueError(f"b256 must be 32 bytes, got {len(raw)}")
    return raw


def sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


class Signer:
    def __init__(self, private_key: str | bytes):
        if isinstance(private_key, str):
            pk_hex = private_key
            if pk_hex.startswith("0x"):
                pk_hex = pk_hex[2:]
            if len(pk_hex) == 64:
                pk_bytes = bytes.fromhex(pk_hex)
            else:
                raise ValueError("Invalid private key length")
        else:
            if len(private_key) != 32:
                raise ValueError("Private key must be 32 bytes")
            pk_bytes = private_key

        self._priv = PrivateKey(pk_bytes)
        # Uncompressed public key (64 bytes, no 0x04 prefix)
        pub = self._priv.public_key.format(compressed=False)[1:]
        self.public_key = pub
        self.private_key = pk_bytes
        self.address = hexlify(hashlib.sha256(pub).digest())

    @staticmethod
    def generate_private_key() -> bytes:
        return secrets.token_bytes(32)

    def sign(self, data: bytes | str) -> str:
        data_bytes = arrayify(data) if isinstance(data, str) else data
        sig65 = self._priv.sign_recoverable(data_bytes, hasher=None)
        r = sig65[:32]
        s = bytearray(sig65[32:64])
        recovery = sig65[64]
        s[0] |= (recovery & 0x01) << 7
        return hexlify(r + bytes(s))


def get_address(bits: str) -> Dict[str, Dict[str, str]]:
    return {"Address": {"bits": bits}}


def encode_option(args: Optional[bytes]) -> bytes:
    if args is not None:
        return concat([encode_u64(1), args])
    return encode_u64(0)


def create_session(address_b256: str, contract_ids: List[str], expiry_ms: Optional[int] = None) -> Dict[str, Any]:
    if expiry_ms is None:
        expiry_ms = int(time.time() * 1000) + 320 * 60 * 1000
    return {
        "session_id": get_address(address_b256),
        "expiry": {"unix": expiry_ms},
        "contract_ids": [{"bits": cid} for cid in contract_ids],
    }


def create_call_to_sign(nonce: int, chain_id: int, func_name: str, arg_bytes: bytes) -> bytes:
    func_name_bytes = to_utf8_bytes(func_name)
    return concat(
        [
            encode_u64(nonce),
            encode_u64(chain_id),
            encode_u64(len(func_name_bytes)),
            func_name_bytes,
            arg_bytes,
        ]
    )


def hash_personal_message(message: bytes) -> str:
    payload = concat(
        [
            to_utf8_bytes(FUEL_MESSAGE_PREFIX),
            to_utf8_bytes(str(len(message))),
            message,
        ]
    )
    return sha256_hex(payload)


def call_contract_to_bytes(
    *,
    contract_id: str,
    function_selector: str,
    amount: int,
    asset_id: str,
    gas: int,
    args: Optional[bytes] = None,
) -> bytes:
    selector_bytes = arrayify(function_selector)
    args_field = None
    if args is not None:
        args_field = concat([encode_u64(len(args)), args])
    return concat(
        [
            arrayify(contract_id),
            encode_u64(len(selector_bytes)),
            selector_bytes,
            encode_u64(amount),
            arrayify(asset_id),
            encode_u64(gas),
            encode_option(args_field),
        ]
    )


def session_sign(signer: Signer, data: bytes) -> str:
    return signer.sign(sha256_hex(data))


def calculate_amount(side: str, price: int, quantity: int, base_decimals: int) -> int:
    if side == OrderSide.Buy:
        return (price * quantity) // (10 ** base_decimals)
    return quantity


# Encoding helpers 


def encode_identity_address(address_b256: str) -> bytes:
    # Enum case order: Address, ContractId
    return concat([encode_u64(0), encode_b256(address_b256)])


def encode_time(unix_ms: int) -> bytes:
    return encode_u64(unix_ms)


def encode_contract_id(contract_id: str) -> bytes:
    return encode_b256(contract_id)


def encode_vec_contract_ids(contract_ids: List[str]) -> bytes:
    items = b"".join(encode_contract_id(cid) for cid in contract_ids)
    return concat([encode_u64(len(contract_ids)), items])


def encode_session(session: Dict[str, Any]) -> bytes:
    session_id_bits = session["session_id"]["Address"]["bits"]
    expiry_unix = session["expiry"]["unix"]
    contract_ids = [c["bits"] for c in session["contract_ids"]]
    return concat(
        [
            encode_identity_address(session_id_bits),
            encode_time(int(expiry_unix)),
            encode_vec_contract_ids(contract_ids),
        ]
    )


def encode_session_option(session: Optional[Dict[str, Any]]) -> bytes:
    if session is None:
        return encode_u64(0)
    return concat([encode_u64(1), encode_session(session)])


def encode_order_type(order_type: str) -> bytes:
    # Enum case order: Limit, Spot, FillOrKill, PostOnly, Market, BoundedMarket
    mapping = {
        OrderType.Spot: 1,
        OrderType.Market: 4,
    }
    if order_type not in mapping:
        raise ValueError(f"Unsupported order type: {order_type}")
    return encode_u64(mapping[order_type])


def encode_order_args(price: int, quantity: int, order_type: str) -> bytes:
    return concat([encode_u64(price), encode_u64(quantity), encode_order_type(order_type)])


def encode_function_selector(name: str) -> bytes:
    name_bytes = to_utf8_bytes(name)
    return concat([encode_u64(len(name)), name_bytes])


# Network Helpers 


def get_chain_id() -> int:
    query = "query getChain { chain { consensusParameters { chainId } } }"
    resp = requests.post(PROVIDER_URL, json={"query": query}, timeout=30)
    resp.raise_for_status()
    payload = resp.json()
    chain_id_str = payload["data"]["chain"]["consensusParameters"]["chainId"]
    return int(chain_id_str, 0)


# Main 


def main() -> None:
    # 1. Setup provider chainId and owner
    owner_signer = Signer(OWNER_PRIVATE_KEY)
    owner_address = owner_signer.address
    chain_id = get_chain_id()

    print("Owner Address:", owner_address)
    print("Chain ID:", chain_id)

    # 2. Generate random session signer
    session_private_key = Signer.generate_private_key()
    session_signer = Signer(session_private_key)
    print("Session Private Key:", hexlify(session_private_key))
    print("Session Address:", session_signer.address)

    # 3. Create/fetch trading account
    account_res = requests.post(
        f"{REST_URL}/v1/accounts",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        data=json.dumps({"identity": {"Address": owner_address}}),
        timeout=30,
    ).json()

    trade_account_id = account_res.get("trade_account_id")
    if not trade_account_id:
        raise RuntimeError("Trading account not found")

    print("Trade Account ID:", trade_account_id)

    # 4. Fetch nonce from the request
    nonce = int(account_res.get("nonce")[2:])
    print("Nonce:", str(nonce))

    # 5. Fetch markets to get contract IDs and market info
    markets_res = requests.get(f"{REST_URL}/v1/markets", timeout=30).json()
    markets = markets_res.get("markets", [])
    if not markets:
        raise RuntimeError("No markets returned from API")

    contract_ids = [m["contract_id"] for m in markets]
    market = markets[0]
    print("Contract IDs:", contract_ids)
    print("Using market:", market["market_id"])

    # 6. Create session input and bytes to sign
    session = create_session(session_signer.address, contract_ids)
    session_arg_bytes = encode_session_option(session)
    bytes_to_sign = create_call_to_sign(nonce, chain_id, "set_session", session_arg_bytes)

    # 7. Sign with owner (personal sign format)
    message_hash = hash_personal_message(bytes_to_sign)
    signature = owner_signer.sign(message_hash)

    # 8. Build session API params
    session_params = {
        "nonce": str(nonce),
        "contract_id": trade_account_id,
        "session_id": {"Address": session_signer.address},
        "contract_ids": contract_ids,
        "signature": {"Secp256k1": signature},
        "expiry": str(session["expiry"]["unix"]),
    }

    print("Session Params:", json.dumps(session_params, indent=2))

    # 9. Create session via API
    session_res = requests.put(
        f"{REST_URL}/v1/session",
        headers={
            "Content-Type": "application/json",
            "o2-owner-id": owner_address,
            "x-rate-limit-id": owner_address,
        },
        data=json.dumps(session_params),
        timeout=30,
    ).json()

    print("Session Response:", session_res)

    # CREATE ORDER 
    print("\nCreating Order")

    # 10. Use incremented nonce (session creation used one nonce)
    order_nonce = nonce + 1
    print("Order Nonce:", str(order_nonce))

    # 11. Order parameters
    order_side = OrderSide.Buy
    order_type = OrderType.Spot
    price = 1000000000000  # 1000.0 in 9 decimals
    quantity = 100000000  # 0.1 in 9 decimals

    # 12. Create order args
    base_decimals = int(market["base"]["decimals"])

    forward_amount = calculate_amount(order_side, price, quantity, base_decimals)
    forward_asset_id = (
        market["quote"]["asset"] if order_side == OrderSide.Buy else market["base"]["asset"]
    )

    # 13. Prepare call params
    gas_limit_default = U64_MAX

    # 14. Encode call to bytes
    order_contract_id = market["contract_id"]
    order_selector_bytes = encode_function_selector("create_order")
    order_arg_bytes = encode_order_args(price, quantity, order_type)

    call_bytes = call_contract_to_bytes(
        contract_id=order_contract_id,
        function_selector=hexlify(order_selector_bytes),
        amount=forward_amount,
        asset_id=forward_asset_id,
        gas=gas_limit_default,
        args=order_arg_bytes,
    )

    # 15. Sign with session signer: nonce + length + bytes
    num_calls = 1
    session_bytes_to_sign = concat(
        [encode_u64(order_nonce), encode_u64(num_calls), call_bytes]
    )
    session_signature = session_sign(session_signer, session_bytes_to_sign)

    # 16. Build session actions payload
    actions_payload = {
        "actions": [
            {
                "market_id": market["market_id"],
                "actions": [
                    {
                        "CreateOrder": {
                            "side": order_side,
                            "order_type": order_type,
                            "price": str(price),
                            "quantity": str(quantity),
                        }
                    }
                ],
            }
        ],
        "signature": {"Secp256k1": session_signature},
        "nonce": str(order_nonce),
        "trade_account_id": trade_account_id,
        "session_id": {"Address": session_signer.address},
        "variable_outputs": 0,
        "collect_orders": False,
    }

    print("Actions Payload:", json.dumps(actions_payload, indent=2))

    # 17. Submit order via session actions API
    order_res = requests.post(
        f"{REST_URL}/v1/session/actions",
        headers={
            "Content-Type": "application/json",
            "o2-owner-id": owner_address,
            "x-rate-limit-id": owner_address,
        },
        data=json.dumps(actions_payload),
        timeout=30,
    ).json()

    print("Order Response:", order_res)


if __name__ == "__main__":
    main()
