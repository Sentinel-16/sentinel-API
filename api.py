"""
Sentinel Risk Engine API v1.1.0
================================
The same scoring engine from the Chrome extension, now as a REST API.
Any wallet, dApp, or service can send a transaction and get back a risk assessment.

Endpoints:
  POST /v1/score          — Score a transaction
  POST /v1/score/signature — Score a signature request
  GET  /v1/address/:addr  — Check address
  GET  /v1/health         — Health check
  GET  /v1/chains         — List supported chains

Run:
  pip install flask requests --break-system-packages
  python api.py
"""

from flask import Flask, request, jsonify
import requests
import time
import os
import re
import json as json_module

app = Flask(__name__)

@app.after_request
def prettify_json(response):
    if 'application/json' in response.content_type:
        try:
            data = json_module.loads(response.get_data())
            response.set_data(json_module.dumps(data, indent=2))
        except Exception:
            pass
    return response


# ═══════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════

API_KEYS = {
    "ETHERSCAN": os.environ.get("ETHERSCAN_KEY", "7623I5SXM63J31566XA2EFS4R968SI9C4V"),
    "GOPLUS": os.environ.get("GOPLUS_KEY", "B4CkqaueDfB4bQ1HEadN350YpGjd5gBQ"),
    "TENDERLY": os.environ.get("TENDERLY_KEY", "7vz2ktra55ApEur2zkgADXW3L378-eNI"),
    "TENDERLY_ACCOUNT": os.environ.get("TENDERLY_ACCOUNT", ""),
    "TENDERLY_PROJECT": os.environ.get("TENDERLY_PROJECT", ""),
}

SENTINEL_API_KEY = os.environ.get("SENTINEL_API_KEY", "dev-key-change-in-production")

CHAIN_CONFIG = {
    1:     {"name": "Ethereum",  "explorer": "api.etherscan.io",            "goplusId": "1"},
    137:   {"name": "Polygon",   "explorer": "api.polygonscan.com",         "goplusId": "137"},
    42161: {"name": "Arbitrum",  "explorer": "api.arbiscan.io",             "goplusId": "42161"},
    8453:  {"name": "Base",      "explorer": "api.basescan.org",            "goplusId": "8453"},
    10:    {"name": "Optimism",  "explorer": "api-optimistic.etherscan.io", "goplusId": "10"},
    56:    {"name": "BSC",       "explorer": "api.bscscan.com",             "goplusId": "56"},
    43114: {"name": "Avalanche", "explorer": "api.snowtrace.io",            "goplusId": "43114"},
    11155111: {"name": "Sepolia","explorer": "api-sepolia.etherscan.io",    "goplusId": "1"},
}

RISK_WEIGHTS = {
    "SCAM_ADDRESS":         {"score": 95, "override": True},
    "UNLIMITED_APPROVAL":   {"score": 60, "override": False},
    "CONTRACT_NEW":         {"score": 30, "override": False},
    "CONTRACT_UNVERIFIED":  {"score": 25, "override": False},
    "NO_CONTRACT_CODE":     {"score": 35, "override": False},
    "PERMIT_SIGNATURE":     {"score": 45, "override": False},
    "ADDRESS_SIMILAR":      {"score": 35, "override": False},
    "LARGE_OUTFLOW":        {"score": 20, "override": False},
    "SUSPICIOUS_ADDRESS":   {"score": 30, "override": False},
    "FIRST_INTERACTION":    {"score": 10, "override": False},
    "DRAIN_PATTERN":        {"score": 90, "override": True},
    # NEW checks
    "SET_APPROVAL_FOR_ALL": {"score": 70, "override": False},
    "HONEYPOT_TOKEN":       {"score": 85, "override": True},
    "DRAINER_SIGNATURE":    {"score": 90, "override": True},
    "EMPTY_RECIPIENT":      {"score": 40, "override": False},
    "LARGE_ETH_TRANSFER":   {"score": 25, "override": False},
    "KNOWN_PHISHING_SIG":   {"score": 80, "override": True},
    "MULTIPLE_APPROVALS":   {"score": 50, "override": False},
    "ETH_SIGN_DANGEROUS":   {"score": 75, "override": False},
}

KNOWN_ADDRESSES = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap Universal Router",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router V2",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5 Router",
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Permit2",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
    "0x514910771af9ca656af840dff83e8264ecf986ca": "LINK",
    "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": "Aave",
    "0x00000000006c3852cbef3e08e8df289169ede581": "OpenSea Seaport",
    "0x00000000000001ad428e4906ae43d8f9852d0dd6": "OpenSea Seaport 1.5",
}

# Known drainer function signatures
DRAINER_SIGNATURES = {
    "0x5fd3ad18": "SecurityUpdate",
    "0x2d0335ab": "ClaimRewards",
    "0x8a4068dd": "ClaimAirdrop",
    "0x715488af": "multicall_drain",
    "0xb2bd16ab": "Connect",
    "0x9b1ccc15": "SwapExactETH",
    "0x2e1a7d4d": "withdraw",  # suspicious if to unverified contract
    "0xf3fef3a3": "withdraw_to",
    "0x3ccfd60b": "withdraw_all",
}

# Common phishing function names (matched against verified source code)
PHISHING_FUNCTION_NAMES = [
    "securityupdate", "claimreward", "claimairdrop", "connectwallet",
    "enabletrading", "starttrading", "activate", "safeclaim",
]

MAX_UINT256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
MAX_UINT256_DEC = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
MAX_UINT160_DEC = "1461501637330902918203684832716283019655932542975"

TOKEN_NAMES = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
}

# ETH transfer threshold for LARGE_ETH_TRANSFER flag (in ETH)
LARGE_ETH_THRESHOLD = 5.0


# ═══════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════

def get_chain(chain_id):
    return CHAIN_CONFIG.get(int(chain_id), CHAIN_CONFIG[1])

def explorer_url(chain):
    return f"https://{chain['explorer']}/api"

def label_address(addr):
    if not addr:
        return "unknown"
    name = KNOWN_ADDRESSES.get(addr.lower())
    if name:
        return name
    return addr[:6] + "..." + addr[-4:]

def compute_score(factors):
    score = 0
    max_override = 0
    for f in factors:
        w = RISK_WEIGHTS.get(f["type"])
        if not w:
            continue
        if w["override"] and w["score"] > max_override:
            max_override = w["score"]
        score += w["score"]
    score = max(score, max_override)
    return min(score, 100)

def get_level(score):
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"

def lookup_function_sig(sig_hex):
    """Look up 4-byte function signature against known drainer sigs and public databases"""
    # Check local drainer database first
    if sig_hex.lower() in DRAINER_SIGNATURES:
        return {"name": DRAINER_SIGNATURES[sig_hex.lower()], "is_drainer": True}
    # Try 4byte.directory for function name
    try:
        r = requests.get(
            f"https://www.4byte.directory/api/v1/signatures/?hex_signature={sig_hex}",
            timeout=3
        )
        if r.ok:
            data = r.json()
            results = data.get("results", [])
            if results:
                name = results[0].get("text_signature", "unknown")
                return {"name": name, "is_drainer": False}
    except Exception:
        pass
    return {"name": "unknown", "is_drainer": False}


# ═══════════════════════════════════════════════
# CHECK FUNCTIONS — Live API calls
# ═══════════════════════════════════════════════

def check_scam_address(address, chain):
    try:
        r = requests.get(
            f"https://api.gopluslabs.io/api/v1/address_security/{address}",
            params={"chain_id": chain["goplusId"]},
            headers={"Authorization": API_KEYS["GOPLUS"]},
            timeout=5
        )
        data = r.json()
        if "result" in data and data["result"]:
            result = data["result"]
            flags = []
            if result.get("blacklist_doubt") == "1": flags.append("blacklisted")
            if result.get("phishing_activities") == "1": flags.append("phishing")
            if result.get("stealing_attack") == "1": flags.append("stealing attack")
            if result.get("honeypot_related_address") == "1": flags.append("honeypot related")
            if result.get("financial_crime") == "1": flags.append("financial crime")
            if result.get("malicious_mining_activities") == "1": flags.append("malicious mining")
            if result.get("darkweb_transactions") == "1": flags.append("darkweb activity")
            if result.get("cybercrime") == "1": flags.append("cybercrime")
            if result.get("money_laundering") == "1": flags.append("money laundering")
            if result.get("number_of_malicious_contracts_created", "0") != "0": flags.append("created malicious contracts")
            return {"is_scam": len(flags) > 0, "reason": ", ".join(flags)}
        return {"is_scam": False, "reason": ""}
    except Exception as e:
        return {"is_scam": False, "reason": "", "error": str(e)}


def check_honeypot_token(address, chain):
    """Check if a token is a honeypot (can buy but can't sell)"""
    try:
        r = requests.get(
            f"https://api.gopluslabs.io/api/v1/token_security/{chain['goplusId']}",
            params={"contract_addresses": address},
            headers={"Authorization": API_KEYS["GOPLUS"]},
            timeout=5
        )
        data = r.json()
        result = data.get("result", {}).get(address.lower(), {})
        if not result:
            return {"is_honeypot": False}

        flags = []
        is_honeypot = result.get("is_honeypot") == "1"
        if is_honeypot:
            flags.append("token cannot be sold")
        if result.get("is_mintable") == "1":
            flags.append("token is mintable (supply can be inflated)")
        if result.get("can_take_back_ownership") == "1":
            flags.append("ownership can be reclaimed")
        if result.get("owner_change_balance") == "1":
            flags.append("owner can change balances")
        if result.get("hidden_owner") == "1":
            flags.append("hidden owner detected")
        if result.get("selfdestruct") == "1":
            flags.append("contract can self-destruct")
        if result.get("external_call") == "1":
            flags.append("contract makes external calls")
        if result.get("is_proxy") == "1":
            flags.append("proxy contract (logic can be changed)")
        if result.get("transfer_pausable") == "1":
            flags.append("transfers can be paused")
        if result.get("trading_cooldown") == "1":
            flags.append("trading cooldown enabled")
        if result.get("is_anti_whale") == "1":
            flags.append("anti-whale mechanism")
        if result.get("cannot_sell_all") == "1":
            flags.append("cannot sell full balance")

        buy_tax = result.get("buy_tax", "0")
        sell_tax = result.get("sell_tax", "0")
        try:
            if float(sell_tax) > 10:
                flags.append(f"high sell tax: {sell_tax}%")
            if float(buy_tax) > 10:
                flags.append(f"high buy tax: {buy_tax}%")
        except (ValueError, TypeError):
            pass

        return {
            "is_honeypot": is_honeypot or len(flags) > 2,
            "flags": flags,
            "buy_tax": buy_tax,
            "sell_tax": sell_tax,
            "holder_count": result.get("holder_count", "unknown"),
            "lp_holder_count": result.get("lp_holder_count", "unknown"),
        }
    except Exception as e:
        return {"is_honeypot": False, "error": str(e)}


def check_contract_age(address, chain):
    try:
        r = requests.get(
            explorer_url(chain),
            params={
                "module": "contract",
                "action": "getcontractcreation",
                "contractaddresses": address,
                "apikey": API_KEYS["ETHERSCAN"]
            },
            timeout=5
        )
        data = r.json()
        if data.get("result") and isinstance(data["result"], list) and len(data["result"]) > 0 and data["result"][0].get("timeStamp"):
            created = int(data["result"][0]["timeStamp"])
            age_seconds = time.time() - created
            age_hours = int(age_seconds / 3600)
            age_days = int(age_hours / 24)
            age_str = f"{age_days} days ago" if age_days > 0 else f"{age_hours} hours ago"
            return {"is_new": age_seconds < 86400, "age": age_str}
        return {"is_new": False, "age": "not a contract"}
    except Exception as e:
        return {"is_new": False, "age": "unknown", "error": str(e)}


def check_contract_verified(address, chain):
    try:
        r = requests.get(
            explorer_url(chain),
            params={
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": API_KEYS["ETHERSCAN"]
            },
            timeout=5
        )
        data = r.json()
        if data.get("result") and isinstance(data["result"], list) and len(data["result"]) > 0:
            source = data["result"][0].get("SourceCode", "")
            contract_name = data["result"][0].get("ContractName", "")
            return {
                "verified": source != "" and source is not None,
                "contract_name": contract_name
            }
        return {"verified": False, "contract_name": ""}
    except Exception as e:
        return {"verified": False, "contract_name": "", "error": str(e)}


def check_suspicious_address(address):
    if not address:
        return {"suspicious": False}
    clean = address.lower().replace("0x", "")
    unique_chars = len(set(clean))
    if unique_chars <= 3:
        return {"suspicious": True, "reason": f"Address has suspicious repeating pattern ({unique_chars} unique characters)"}
    if "dead" in clean or "0000000000" in clean:
        return {"suspicious": True, "reason": "Address matches a burn/dead address pattern"}
    if clean.startswith("000000000000000000000000000000"):
        return {"suspicious": True, "reason": "Address is mostly zeros"}
    return {"suspicious": False}


def check_address_balance(address, chain):
    """Check if recipient address has any ETH balance or transaction history"""
    try:
        r = requests.get(
            explorer_url(chain),
            params={
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest",
                "apikey": API_KEYS["ETHERSCAN"]
            },
            timeout=5
        )
        data = r.json()
        if data.get("result") and isinstance(data["result"], str):
            balance_wei = int(data["result"])
            balance_eth = balance_wei / 1e18
            return {"balance_eth": balance_eth, "is_empty": balance_eth == 0}
        return {"balance_eth": 0, "is_empty": True}
    except Exception as e:
        return {"balance_eth": 0, "is_empty": True, "error": str(e)}


def check_address_tx_count(address, chain):
    """Check how many transactions an address has — low count = suspicious"""
    try:
        r = requests.get(
            explorer_url(chain),
            params={
                "module": "proxy",
                "action": "eth_getTransactionCount",
                "address": address,
                "tag": "latest",
                "apikey": API_KEYS["ETHERSCAN"]
            },
            timeout=5
        )
        data = r.json()
        if data.get("result"):
            tx_count = int(data["result"], 16)
            return {"tx_count": tx_count, "is_new_address": tx_count < 5}
        return {"tx_count": 0, "is_new_address": True}
    except Exception as e:
        return {"tx_count": 0, "is_new_address": True, "error": str(e)}


def simulate_tx(tx, chain):
    try:
        start = time.time()
        if API_KEYS["TENDERLY_ACCOUNT"] and API_KEYS["TENDERLY_PROJECT"]:
            url = f"https://api.tenderly.co/api/v1/account/{API_KEYS['TENDERLY_ACCOUNT']}/project/{API_KEYS['TENDERLY_PROJECT']}/simulate"
        else:
            url = "https://api.tenderly.co/api/v1/simulate"

        r = requests.post(url, json={
            "network_id": str(chain.get("id", 1)),
            "from": tx.get("from", "0x0000000000000000000000000000000000000000"),
            "to": tx.get("to", ""),
            "input": tx.get("data", "0x"),
            "value": tx.get("value", "0x0"),
            "gas": 8000000,
            "save": False,
            "simulation_type": "quick"
        }, headers={
            "X-Access-Key": API_KEYS["TENDERLY"],
            "Content-Type": "application/json"
        }, timeout=10)

        latency = int((time.time() - start) * 1000)

        if not r.ok:
            return {"success": False, "latency_ms": latency}

        data = r.json()
        sim = data.get("simulation", data.get("transaction", {}))
        balance_changes = []
        if sim.get("transaction_info", {}).get("balance_changes"):
            for change in sim["transaction_info"]["balance_changes"]:
                balance_changes.append({
                    "token": change.get("token_info", {}).get("symbol", "ETH"),
                    "delta": change.get("delta", "0")
                })

        return {"success": True, "latency_ms": latency, "balance_changes": balance_changes}
    except Exception as e:
        return {"success": False, "latency_ms": 0}


# ═══════════════════════════════════════════════
# DECODERS
# ═══════════════════════════════════════════════

def decode_approval(data_hex):
    """Decode ERC-20 approve(address,uint256)"""
    if len(data_hex) < 138:
        return None
    spender = "0x" + data_hex[34:74]
    amount_hex = data_hex[74:138]
    unlimited = amount_hex.replace("0", "").lower() == "f" * len(amount_hex.replace("0", ""))
    if amount_hex.lower().strip("0") == "" and len(amount_hex) > 10:
        unlimited = False
    if amount_hex.lower() == MAX_UINT256:
        unlimited = True
    return {"spender": spender, "unlimited": unlimited, "amount_hex": amount_hex}


def decode_set_approval_for_all(data_hex):
    """Decode ERC-721/1155 setApprovalForAll(address,bool)"""
    if len(data_hex) < 138:
        return None
    operator = "0x" + data_hex[34:74]
    approved_hex = data_hex[74:138]
    approved = approved_hex.strip("0") != "" and approved_hex[-1] == "1"
    return {"operator": operator, "approved": approved}


def decode_permit(typed_data):
    """Decode Permit/Permit2 typed data"""
    message = typed_data.get("message", {})
    domain = typed_data.get("domain", {})
    details = message.get("details", {})

    amount = str(details.get("amount", message.get("value", message.get("amount", "0"))))
    token = details.get("token", domain.get("verifyingContract", "unknown"))
    spender = message.get("spender", message.get("operator", "unknown"))
    unlimited = amount in [MAX_UINT256_DEC, MAX_UINT160_DEC]

    token_name = TOKEN_NAMES.get(token.lower(), domain.get("name", "tokens"))

    return {
        "spender": spender,
        "token": token,
        "token_name": token_name,
        "amount": amount,
        "unlimited": unlimited
    }


# ═══════════════════════════════════════════════
# SCORING ENGINE
# ═══════════════════════════════════════════════

def score_transaction(tx, chain_id=1):
    """Score an eth_sendTransaction"""
    chain = get_chain(chain_id)
    to = (tx.get("to") or "").lower()
    value = int(tx.get("value", "0x0"), 16) if isinstance(tx.get("value"), str) else int(tx.get("value", 0))
    data = tx.get("data", "0x")

    factors = []
    details = {"chain": chain["name"], "chain_id": chain_id, "to": to, "to_label": label_address(to)}
    summary = ""

    # ── Decode transaction type ──
    if data.startswith("0x095ea7b3"):
        # ERC-20 approve
        approval = decode_approval(data)
        if approval:
            details["type"] = "Token Approval"
            details["spender"] = approval["spender"]
            details["spender_label"] = label_address(approval["spender"])
            details["unlimited"] = approval["unlimited"]
            if approval["unlimited"]:
                factors.append({"type": "UNLIMITED_APPROVAL", "detail": "Unlimited token approval requested"})
                summary = f"Grants UNLIMITED spending access to your tokens. The approved address ({label_address(approval['spender'])}) can drain your entire balance at any time."
                details["suggestion"] = "Consider approving only the amount needed instead of unlimited."
            else:
                summary = f"Approves token spending by {label_address(approval['spender'])}."

    elif data.startswith("0xa22cb465"):
        # ERC-721/1155 setApprovalForAll — #1 NFT drainer pattern
        approval = decode_set_approval_for_all(data)
        if approval and approval["approved"]:
            details["type"] = "NFT Approval (setApprovalForAll)"
            details["operator"] = approval["operator"]
            details["operator_label"] = label_address(approval["operator"])
            factors.append({"type": "SET_APPROVAL_FOR_ALL", "detail": f"Grants full access to ALL your NFTs in this collection to {label_address(approval['operator'])}"})
            summary = f"Grants {label_address(approval['operator'])} permission to transfer ALL your NFTs from this contract. This is the #1 method used in NFT phishing attacks."
            details["suggestion"] = "Only approve setApprovalForAll for marketplaces you trust (OpenSea, Blur, etc)."

            # Extra suspicious if operator is not a known marketplace
            if approval["operator"].lower() not in KNOWN_ADDRESSES:
                factors.append({"type": "DRAINER_SIGNATURE", "detail": "setApprovalForAll to unknown operator — high probability of NFT drain"})
        elif approval and not approval["approved"]:
            details["type"] = "NFT Revoke (setApprovalForAll)"
            summary = "Revokes NFT access. This is a safe operation."

    elif data == "0x" and value > 0:
        # Native ETH transfer
        details["type"] = "Native Transfer"
        value_eth = value / 1e18
        details["value_eth"] = value_eth
        summary = f"Sends {value_eth:.6f} ETH to {label_address(to)}."

        if value_eth >= LARGE_ETH_THRESHOLD:
            factors.append({"type": "LARGE_ETH_TRANSFER", "detail": f"Large transfer: {value_eth:.2f} ETH (${value_eth * 2000:.0f} approx)"})

    else:
        # Contract interaction — check function signature
        func_sig = data[:10] if len(data) >= 10 else data
        sig_info = lookup_function_sig(func_sig)

        details["type"] = "Contract Interaction"
        details["function_sig"] = func_sig
        details["function_name"] = sig_info["name"]

        if sig_info["is_drainer"]:
            factors.append({"type": "DRAINER_SIGNATURE", "detail": f"Known drainer function detected: {sig_info['name']}()"})
            summary = f"DANGER: This transaction calls {sig_info['name']}(), which is a known drainer function signature. Do NOT proceed."
        else:
            summary = f"Calls {sig_info['name']}() on contract at {label_address(to)}."

    # ── Run checks ──

    # Scam address check (GoPlus)
    scam = check_scam_address(to, chain)
    if scam["is_scam"]:
        factors.append({"type": "SCAM_ADDRESS", "detail": f"Address flagged as scam: {scam['reason']}"})
    details["scam_check"] = scam

    # Contract age check
    age = check_contract_age(to, chain)
    if age["is_new"]:
        factors.append({"type": "CONTRACT_NEW", "detail": f"Contract deployed {age['age']} on {chain['name']}"})
    details["contract_age"] = age["age"]

    # Contract verification check
    verified = check_contract_verified(to, chain)
    if not verified["verified"]:
        factors.append({"type": "CONTRACT_UNVERIFIED", "detail": f"Contract not verified on {chain['name']} block explorer"})
        details["verified"] = False
    else:
        details["verified"] = True
        details["contract_name"] = verified.get("contract_name", "")

    # Approval to non-contract
    if data.startswith("0x095ea7b3") and age["age"] == "not a contract":
        factors.append({"type": "NO_CONTRACT_CODE", "detail": "Token approval targets a regular address (not a smart contract)"})

    # setApprovalForAll to non-contract
    if data.startswith("0xa22cb465") and age["age"] == "not a contract":
        factors.append({"type": "NO_CONTRACT_CODE", "detail": "NFT approval targets a regular address (not a smart contract)"})

    # Suspicious address pattern
    susp = check_suspicious_address(to)
    if susp.get("suspicious"):
        factors.append({"type": "SUSPICIOUS_ADDRESS", "detail": susp["reason"]})

    # NEW: Empty recipient check
    if data != "0x" or value > 0:
        balance_info = check_address_balance(to, chain)
        tx_count = check_address_tx_count(to, chain)
        if balance_info["is_empty"] and tx_count.get("is_new_address", True) and age["age"] == "not a contract":
            factors.append({"type": "EMPTY_RECIPIENT", "detail": f"Recipient has zero balance and {tx_count.get('tx_count', 0)} transactions — possible disposable drainer address"})
        details["recipient_balance_eth"] = balance_info.get("balance_eth", 0)
        details["recipient_tx_count"] = tx_count.get("tx_count", 0)

    # NEW: Honeypot check for token interactions
    if data.startswith(("0x095ea7b3", "0xa9059cbb", "0x23b872dd")):
        honeypot = check_honeypot_token(to, chain)
        if honeypot.get("is_honeypot"):
            factors.append({"type": "HONEYPOT_TOKEN", "detail": f"Token flagged as honeypot: {', '.join(honeypot.get('flags', []))}"})
            details["honeypot"] = honeypot

    # Simulate transaction
    sim = simulate_tx(tx, chain)
    if sim.get("success"):
        details["simulation"] = sim

    # ── Compute final score ──
    score = compute_score(factors)
    level = get_level(score)

    return {
        "score": score,
        "level": level,
        "blocked": score > 50,
        "recommendation": "block" if score > 80 else "warn" if score > 20 else "allow",
        "summary": summary,
        "factors": factors,
        "details": details,
        "chain": chain["name"],
        "timestamp": int(time.time())
    }


def score_signature(method, typed_data, chain_id=1):
    """Score a signature request (eth_signTypedData, personal_sign, eth_sign)"""
    chain = get_chain(chain_id)
    factors = []
    details = {"chain": chain["name"], "chain_id": chain_id}
    summary = ""

    if method in ["eth_signTypedData_v4", "eth_signTypedData_v3", "eth_signTypedData"]:
        primary_type = typed_data.get("primaryType", "")
        is_permit = primary_type in ["Permit", "PermitSingle", "PermitBatch"]

        if is_permit:
            permit = decode_permit(typed_data)
            factors.append({"type": "PERMIT_SIGNATURE", "detail": "Gasless token approval (Permit/Permit2)"})
            details["type"] = "Permit Signature"
            details["spender"] = permit["spender"]
            details["spender_label"] = label_address(permit["spender"])
            details["token"] = permit["token"]
            details["token_name"] = permit["token_name"]
            details["unlimited"] = permit["unlimited"]

            amount_str = "ALL" if permit["unlimited"] else permit["amount"]
            summary = f"This signature authorizes {label_address(permit['spender'])} to transfer {amount_str} of your {permit['token_name']} WITHOUT a separate transaction."

            if permit["unlimited"]:
                factors.append({"type": "UNLIMITED_APPROVAL", "detail": "Permit grants unlimited token access"})

            # Check if spender is known
            if permit["spender"].lower() not in KNOWN_ADDRESSES:
                factors.append({"type": "DRAINER_SIGNATURE", "detail": f"Permit spender {label_address(permit['spender'])} is not a recognized protocol"})
        else:
            details["type"] = "Typed Data Signature"
            details["primary_type"] = primary_type
            summary = f"Requests signature on {primary_type} typed data."

    elif method == "eth_sign":
        factors.append({"type": "ETH_SIGN_DANGEROUS", "detail": "eth_sign can authorize ANY action on your wallet. This is the most dangerous signature method."})
        details["type"] = "Dangerous Signature (eth_sign)"
        summary = "CRITICAL: eth_sign can authorize arbitrary actions including draining your entire wallet. Legitimate dApps NEVER use this method. This is almost certainly a scam."

    elif method == "personal_sign":
        details["type"] = "Message Signature"
        summary = "Requests signature on a text message. Generally safe, but verify the message content."

        # Check for suspicious personal_sign messages that look like they contain hex data
        message = typed_data if isinstance(typed_data, str) else str(typed_data)
        if message.startswith("0x") and len(message) > 100:
            factors.append({"type": "KNOWN_PHISHING_SIG", "detail": "personal_sign with hex data — may be disguised transaction authorization"})
            summary = "WARNING: This message signature contains hex data that could authorize a transaction. Verify the content carefully."

    score = compute_score(factors)
    level = get_level(score)

    return {
        "score": score,
        "level": level,
        "blocked": score > 50,
        "recommendation": "block" if score > 80 else "warn" if score > 20 else "allow",
        "summary": summary,
        "factors": factors,
        "details": details,
        "chain": chain["name"],
        "timestamp": int(time.time())
    }


# ═══════════════════════════════════════════════
# AUTH MIDDLEWARE
# ═══════════════════════════════════════════════

def check_auth():
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if SENTINEL_API_KEY == "dev-key-change-in-production":
        return True
    if key != SENTINEL_API_KEY:
        return False
    return True


# ═══════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════

@app.route("/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "engine": "sentinel",
        "version": "1.1.0",
        "chains": len(CHAIN_CONFIG),
        "signals": len(RISK_WEIGHTS),
        "checks": [
            "scam_address_detection",
            "honeypot_token_detection",
            "contract_age_verification",
            "contract_source_verification",
            "unlimited_approval_detection",
            "setApprovalForAll_detection",
            "drainer_signature_detection",
            "suspicious_address_patterns",
            "empty_recipient_detection",
            "large_transfer_detection",
            "permit_signature_analysis",
            "eth_sign_detection",
            "function_signature_lookup",
            "transaction_simulation",
            "recipient_balance_check",
            "recipient_history_check",
        ]
    })


@app.route("/v1/chains", methods=["GET"])
def chains():
    return jsonify({
        "chains": {str(k): v["name"] for k, v in CHAIN_CONFIG.items()}
    })


@app.route("/v1/score", methods=["POST"])
def score_tx_endpoint():
    if not check_auth():
        return jsonify({"error": "Invalid API key"}), 401

    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    if not body.get("to"):
        return jsonify({"error": "'to' address required"}), 400

    chain_id = body.get("chainId", body.get("chain_id", 1))

    tx = {
        "to": body["to"],
        "from": body.get("from", "0x0000000000000000000000000000000000000000"),
        "data": body.get("data", "0x"),
        "value": body.get("value", "0x0"),
    }

    start = time.time()
    result = score_transaction(tx, chain_id)
    result["latency_ms"] = int((time.time() - start) * 1000)

    return jsonify(result)


@app.route("/v1/score/signature", methods=["POST"])
def score_sig_endpoint():
    if not check_auth():
        return jsonify({"error": "Invalid API key"}), 401

    body = request.get_json()
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    method = body.get("method", "eth_signTypedData_v4")
    typed_data = body.get("typedData", body.get("typed_data", {}))
    chain_id = body.get("chainId", body.get("chain_id", 1))

    start = time.time()
    result = score_signature(method, typed_data, chain_id)
    result["latency_ms"] = int((time.time() - start) * 1000)

    return jsonify(result)


@app.route("/v1/address/<address>", methods=["GET"])
def check_address(address):
    """Quick address check — is it known, flagged, or suspicious?"""
    if not check_auth():
        return jsonify({"error": "Invalid API key"}), 401

    chain_id = request.args.get("chain_id", 1, type=int)
    chain = get_chain(chain_id)

    label = label_address(address)
    scam = check_scam_address(address, chain)
    susp = check_suspicious_address(address)
    age = check_contract_age(address, chain)
    verified = check_contract_verified(address, chain)
    balance = check_address_balance(address, chain)
    tx_count = check_address_tx_count(address, chain)

    return jsonify({
        "address": address,
        "label": label,
        "known": label != address[:6] + "..." + address[-4:],
        "scam": scam,
        "suspicious": susp,
        "contract_age": age,
        "verified": verified,
        "balance_eth": balance.get("balance_eth", 0),
        "tx_count": tx_count.get("tx_count", 0),
        "chain": chain["name"]
    })


# ═══════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"""
╔══════════════════════════════════════════════╗
║   Sentinel Risk Engine API v1.1.0            ║
║   Running on http://localhost:{port}            ║
╠══════════════════════════════════════════════╣
║   POST /v1/score            Score a tx       ║
║   POST /v1/score/signature  Score a sig      ║
║   GET  /v1/address/:addr    Check address    ║
║   GET  /v1/health           Health check     ║
║   GET  /v1/chains           List chains      ║
╠══════════════════════════════════════════════╣
║   16 detection checks | 8 chains supported   ║
╚══════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=True)
