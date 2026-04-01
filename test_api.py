"""
Test the Sentinel API with the same 5 attack patterns from the Chrome extension test page.
Run the API first: python api.py
Then run this: python test_api.py
"""

import requests
import json

BASE = "http://localhost:5000"

def test(name, response):
    data = response.json()
    color = "\033[92m" if data.get("level") == "low" else "\033[93m" if data.get("level") == "medium" else "\033[91m"
    reset = "\033[0m"
    blocked = "BLOCKED" if data.get("blocked") else "ALLOWED"
    print(f"\n{color}[{data.get('level','?').upper()} ({data.get('score',0)})] {blocked}{reset}")
    print(f"  {name}")
    print(f"  Summary: {data.get('summary','')}")
    print(f"  Recommendation: {data.get('recommendation','')}")
    if data.get("factors"):
        for f in data["factors"]:
            print(f"    - {f['type']}: {f['detail']}")
    print(f"  Latency: {data.get('latency_ms',0)}ms")

print("=" * 60)
print("Sentinel API Test Suite")
print("=" * 60)

# Health check
r = requests.get(f"{BASE}/v1/health")
print(f"\nHealth: {r.json()}")

# Test 1: Unlimited approval to suspicious address
print("\n" + "-" * 60)
print("TEST 1: Unlimited Token Approval (Badger DAO pattern)")
fake_spender = "1" * 40
max_uint = "f" * 64
data_hex = "0x095ea7b3" + "0" * 24 + fake_spender + max_uint
r = requests.post(f"{BASE}/v1/score", json={
    "to": "0x" + "a" * 40,
    "data": data_hex,
    "chainId": 1
})
test("Unlimited approval to unverified contract", r)

# Test 2: Transfer to suspicious address
print("\n" + "-" * 60)
print("TEST 2: Transfer to 0xdead address")
r = requests.post(f"{BASE}/v1/score", json={
    "to": "0x" + "dead" * 10,
    "data": "0x",
    "value": "0x2386F26FC10000",
    "chainId": 1
})
test("ETH transfer to dead address", r)

# Test 3: Permit2 phishing signature
print("\n" + "-" * 60)
print("TEST 3: Permit2 Phishing Signature")
r = requests.post(f"{BASE}/v1/score/signature", json={
    "method": "eth_signTypedData_v4",
    "typedData": {
        "primaryType": "PermitSingle",
        "domain": {"name": "Permit2", "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
        "message": {
            "details": {
                "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                "expiration": "9999999999",
                "nonce": "0"
            },
            "spender": "0x" + "bad" * 13 + "b",
            "sigDeadline": "9999999999"
        }
    },
    "chainId": 1
})
test("Permit2 unlimited USDC to unknown spender", r)

# Test 4: eth_sign
print("\n" + "-" * 60)
print("TEST 4: Dangerous eth_sign")
r = requests.post(f"{BASE}/v1/score/signature", json={
    "method": "eth_sign",
    "typedData": {},
    "chainId": 1
})
test("eth_sign request", r)

# Test 5: Normal transfer
print("\n" + "-" * 60)
print("TEST 5: Normal Transfer (control)")
r = requests.post(f"{BASE}/v1/score", json={
    "to": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    "data": "0x",
    "value": "0x2386F26FC10000",
    "chainId": 1
})
test("Small ETH transfer to vitalik.eth", r)

# Test 6: Address lookup
print("\n" + "-" * 60)
print("TEST 6: Address Lookup")
r = requests.get(f"{BASE}/v1/address/0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D?chain_id=1")
data = r.json()
print(f"\n  Address: {data.get('address')}")
print(f"  Label: {data.get('label')}")
print(f"  Known: {data.get('known')}")
print(f"  Scam: {data.get('scam',{}).get('is_scam')}")
print(f"  Verified: {data.get('verified',{}).get('verified')}")

# Test 7: Multi-chain (Polygon)
print("\n" + "-" * 60)
print("TEST 7: Polygon Transaction")
r = requests.post(f"{BASE}/v1/score", json={
    "to": "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff",
    "data": "0x",
    "value": "0x0",
    "chainId": 137
})
test("Contract interaction on Polygon", r)

print("\n" + "=" * 60)
print("All tests complete.")
print("=" * 60)
