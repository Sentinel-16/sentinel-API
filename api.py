"""
Sentinel Risk Engine API v1.2.0
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
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    "SET_APPROVAL_FOR_ALL": {"score": 70, "override": False},
    "HONEYPOT_TOKEN":       {"score": 85, "override": True},
    "DRAINER_SIGNATURE":    {"score": 90, "override": True},
    "EMPTY_RECIPIENT":      {"score": 30, "override": False},
    "LARGE_ETH_TRANSFER":   {"score": 25, "override": False},
    "KNOWN_PHISHING_SIG":   {"score": 80, "override": True},
    "MULTIPLE_APPROVALS":   {"score": 50, "override": False},
    "ETH_SIGN_DANGEROUS":   {"score": 75, "override": False},
}

# ── Known addresses with trust levels ──
KNOWN_ADDRESSES = {
    # DEX Routers
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {"name": "Uniswap V2 Router", "trusted": True},
    "0xe592427a0aece92de3edee1f18e0157c05861564": {"name": "Uniswap V3 Router", "trusted": True},
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": {"name": "Uniswap Universal Router", "trusted": True},
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": {"name": "Uniswap Universal Router V2", "trusted": True},
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": {"name": "SushiSwap Router", "trusted": True},
    "0x1111111254eeb25477b68fb85ed929f73a960582": {"name": "1inch V5 Router", "trusted": True},
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": {"name": "0x Exchange Proxy", "trusted": True},
    "0x000000000022d473030f116ddee9f6b43ac78ba3": {"name": "Permit2", "trusted": True},
    # NFT Marketplaces
    "0x00000000006c3852cbef3e08e8df289169ede581": {"name": "OpenSea Seaport", "trusted": True},
    "0x00000000000001ad428e4906ae43d8f9852d0dd6": {"name": "OpenSea Seaport 1.5", "trusted": True},
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": {"name": "OpenSea Seaport 1.6", "trusted": True},
    "0x74312363e45dcaba76c59ec49a7aa8a65a67eed3": {"name": "Blur Exchange", "trusted": True},
    "0xb2ecfe4e4d61f8790bbb9de2d1259b9e2410cea5": {"name": "Blur Pool", "trusted": True},
    # DeFi Protocols
    "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": {"name": "Aave Token", "trusted": True},
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": {"name": "Aave V2 Lending Pool", "trusted": True},
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": {"name": "Aave V3 Pool", "trusted": True},
    "0x5d3a536e4d6dbd6114cc1ead35777bab948e3643": {"name": "Compound cDAI", "trusted": True},
    "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b": {"name": "Compound Comptroller", "trusted": True},
    "0xc3d688b66703497daa19211eedff47f25384cdc3": {"name": "Compound V3 USDC", "trusted": True},
    # Staking
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": {"name": "Lido stETH", "trusted": True},
    # Bridges
    "0x3154cf16ccdb4c6d922629664174b904d80f2c35": {"name": "Base Bridge", "trusted": True},
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": {"name": "Optimism Bridge", "trusted": True},
    "0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a": {"name": "Arbitrum Bridge", "trusted": True},
    # Tokens (known but not trusted for approvals)
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {"name": "USDC", "trusted": False},
    "0xdac17f958d2ee523a2206206994597c13d831ec7": {"name": "USDT", "trusted": False},
    "0x6b175474e89094c44da98b954eedeac495271d0f": {"name": "DAI", "trusted": False},
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": {"name": "WETH", "trusted": False},
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": {"name": "WBTC", "trusted": False},
    "0x514910771af9ca656af840dff83e8264ecf986ca": {"name": "LINK", "trusted": False},
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": {"name": "UNI", "trusted": False},
    "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce": {"name": "SHIB", "trusted": False},
    "0x4d224452801aced8b2f0aebe155379bb5d594381": {"name": "APE", "trusted": False},
}

# Known drainer function signatures
DRAINER_SIGNATURES = {
    "0x5fd3ad18": "SecurityUpdate",
    "0x2d0335ab": "ClaimRewards",
    "0x8a4068dd": "ClaimAirdrop",
    "0x715488af": "multicall_drain",
    "0xb2bd16ab": "Connect",
    "0x9b1ccc15": "SwapExactETH",
    "0xf3fef3a3": "withdraw_to",
    "0x3ccfd60b": "withdraw_all",
}

MAX_UINT256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
MAX_UINT256_DEC = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
MAX_UINT160_DEC = "1461501637330902918203684832716283019655932542975"

TOKEN_NAMES = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
    "0x514910771af9ca656af840dff83e8264ecf986ca": "LINK",
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "UNI",
    "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": "AAVE",
    "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce": "SHIB",
    "0x4d224452801aced8b2f0aebe155379bb5d594381": "APE",
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": "stETH",
}

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
    info = KNOWN_ADDRESSES.get(addr.lower())
    if info:
        return info["name"]
    return addr[:6] + "..." + addr[-4:]

def is_trusted_address(addr):
    if not addr:
        return False
    info = KNOWN_ADDRESSES.get(addr.lower())
    return info.get("trusted", False) if info else False

def get_token_name(addr):
    if not addr:
        return "unknown token"
    return TOKEN_NAMES.get(addr.lower(), label_address(addr))

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
    if sig_hex.lower() in DRAINER_SIGNATURES:
        return {"name": DRAINER_SIGNATURES[sig_hex.lower()], "is_drainer": True}
    try:
        r = requests.get(
            f"https://www.4byte.directory/api/v1/signatures/?hex_signature={sig_hex}",
            timeout=3
        )
        if r.ok:
            data = r.json()
            results = data.get("results", [])
            if results:
                return {"name": results[0].get("text_signature", "unknown"), "is_drainer": False}
    except Exception:
        pass
    return {"name": "unknown", "is_drainer": False}


# ═══════════════════════════════════════════════
# CHECK FUNCTIONS
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
        if result.get("is_honeypot") == "1": flags.append("cannot sell")
        if result.get("is_mintable") == "1": flags.append("mintable")
        if result.get("can_take_back_ownership") == "1": flags.append("ownership reclaimable")
        if result.get("owner_change_balance") == "1": flags.append("owner can change balances")
        if result.get("hidden_owner") == "1": flags.append("hidden owner")
        if result.get("selfdestruct") == "1": flags.append("self-destructable")
        if result.get("is_proxy") == "1": flags.append("proxy (logic can change)")
        if result.get("transfer_pausable") == "1": flags.append("pausable")
        if result.get("cannot_sell_all") == "1": flags.append("cannot sell full balance")
        try:
            if float(result.get("sell_tax", "0")) > 10: flags.append(f"sell tax {result['sell_tax']}%")
            if float(result.get("buy_tax", "0")) > 10: flags.append(f"buy tax {result['buy_tax']}%")
        except (ValueError, TypeError):
            pass
        return {"is_honeypot": result.get("is_honeypot") == "1" or len(flags) > 2, "flags": flags}
    except Exception as e:
        return {"is_honeypot": False, "error": str(e)}


def check_contract_age(address, chain):
    try:
        r = requests.get(explorer_url(chain), params={
            "module": "contract", "action": "getcontractcreation",
            "contractaddresses": address, "apikey": API_KEYS["ETHERSCAN"]
        }, timeout=5)
        data = r.json()
        if data.get("result") and isinstance(data["result"], list) and len(data["result"]) > 0 and data["result"][0].get("timeStamp"):
            created = int(data["result"][0]["timeStamp"])
            age_seconds = time.time() - created
            age_days = int(age_seconds / 86400)
            age_hours = int(age_seconds / 3600)
            age_str = f"{age_days} days" if age_days > 0 else f"{age_hours} hours"
            return {"is_new": age_seconds < 86400, "age": age_str}
        return {"is_new": False, "age": "not a contract"}
    except Exception as e:
        return {"is_new": False, "age": "unknown", "error": str(e)}


def check_contract_verified(address, chain):
    try:
        r = requests.get(explorer_url(chain), params={
            "module": "contract", "action": "getsourcecode",
            "address": address, "apikey": API_KEYS["ETHERSCAN"]
        }, timeout=5)
        data = r.json()
        if data.get("result") and isinstance(data["result"], list) and len(data["result"]) > 0:
            source = data["result"][0].get("SourceCode", "")
            return {"verified": source != "" and source is not None, "contract_name": data["result"][0].get("ContractName", "")}
        return {"verified": False, "contract_name": ""}
    except Exception as e:
        return {"verified": False, "contract_name": "", "error": str(e)}


def check_suspicious_address(address):
    if not address:
        return {"suspicious": False}
    clean = address.lower().replace("0x", "")
    if len(set(clean)) <= 3:
        return {"suspicious": True, "reason": f"Suspicious repeating pattern ({len(set(clean))} unique chars)"}
    if "dead" in clean or "0000000000" in clean:
        return {"suspicious": True, "reason": "Burn/dead address pattern"}
    if clean.startswith("000000000000000000000000000000"):
        return {"suspicious": True, "reason": "Address is mostly zeros"}
    return {"suspicious": False}


def check_address_balance(address, chain):
    try:
        r = requests.get(explorer_url(chain), params={
            "module": "account", "action": "balance",
            "address": address, "tag": "latest", "apikey": API_KEYS["ETHERSCAN"]
        }, timeout=5)
        data = r.json()
        if data.get("result") and isinstance(data["result"], str):
            bal = int(data["result"]) / 1e18
            return {"balance_eth": round(bal, 6), "is_empty": bal == 0}
        return {"balance_eth": 0, "is_empty": True}
    except Exception as e:
        return {"balance_eth": 0, "is_empty": True, "error": str(e)}


def check_address_tx_count(address, chain):
    try:
        r = requests.get(explorer_url(chain), params={
            "module": "proxy", "action": "eth_getTransactionCount",
            "address": address, "tag": "latest", "apikey": API_KEYS["ETHERSCAN"]
        }, timeout=5)
        data = r.json()
        if data.get("result"):
            count = int(data["result"], 16)
            return {"tx_count": count, "is_new_address": count < 5}
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
            "to": tx.get("to", ""), "input": tx.get("data", "0x"),
            "value": tx.get("value", "0x0"), "gas": 8000000,
            "save": False, "simulation_type": "quick"
        }, headers={"X-Access-Key": API_KEYS["TENDERLY"], "Content-Type": "application/json"}, timeout=10)
        latency = int((time.time() - start) * 1000)
        if not r.ok:
            return {"success": False, "latency_ms": latency}
        data = r.json()
        sim = data.get("simulation", data.get("transaction", {}))
        changes = []
        if sim.get("transaction_info", {}).get("balance_changes"):
            for c in sim["transaction_info"]["balance_changes"]:
                changes.append({"token": c.get("token_info", {}).get("symbol", "ETH"), "delta": c.get("delta", "0")})
        return {"success": True, "latency_ms": latency, "balance_changes": changes}
    except Exception:
        return {"success": False, "latency_ms": 0}


# ═══════════════════════════════════════════════
# PARALLEL CHECK RUNNER
# ═══════════════════════════════════════════════

def run_checks_parallel(address, chain, tx=None):
    results = {}
    def _scam(): results["scam"] = check_scam_address(address, chain)
    def _age(): results["age"] = check_contract_age(address, chain)
    def _verified(): results["verified"] = check_contract_verified(address, chain)
    def _balance(): results["balance"] = check_address_balance(address, chain)
    def _tx_count(): results["tx_count"] = check_address_tx_count(address, chain)
    def _simulate():
        if tx: results["simulation"] = simulate_tx(tx, chain)
        else: results["simulation"] = {"success": False}

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(t) for t in [_scam, _age, _verified, _balance, _tx_count, _simulate]]
        for f in as_completed(futures):
            try: f.result(timeout=12)
            except Exception: pass
    return results


# ═══════════════════════════════════════════════
# DECODERS
# ═══════════════════════════════════════════════

def decode_approval(data_hex):
    if len(data_hex) < 138: return None
    spender = "0x" + data_hex[34:74]
    amount_hex = data_hex[74:138]
    unlimited = False
    if amount_hex.lower() == MAX_UINT256: unlimited = True
    elif amount_hex.replace("0", "").lower() == "f" * len(amount_hex.replace("0", "")): unlimited = True
    if amount_hex.lower().strip("0") == "" and len(amount_hex) > 10: unlimited = False
    return {"spender": spender, "unlimited": unlimited, "amount_hex": amount_hex}


def decode_set_approval_for_all(data_hex):
    if len(data_hex) < 138: return None
    operator = "0x" + data_hex[34:74]
    approved = data_hex[74:138].strip("0") != "" and data_hex[137] == "1"
    return {"operator": operator, "approved": approved}


def decode_permit(typed_data):
    message = typed_data.get("message", {})
    domain = typed_data.get("domain", {})
    details = message.get("details", {})
    amount = str(details.get("amount", message.get("value", message.get("amount", "0"))))
    token = details.get("token", domain.get("verifyingContract", "unknown"))
    spender = message.get("spender", message.get("operator", "unknown"))
    unlimited = amount in [MAX_UINT256_DEC, MAX_UINT160_DEC]
    token_name = TOKEN_NAMES.get(token.lower(), domain.get("name", "tokens"))
    return {"spender": spender, "token": token, "token_name": token_name, "amount": amount, "unlimited": unlimited}


# ═══════════════════════════════════════════════
# SCORING ENGINE
# ═══════════════════════════════════════════════

def score_transaction(tx, chain_id=1):
    chain = get_chain(chain_id)
    to = (tx.get("to") or "").lower()
    value = int(tx.get("value", "0x0"), 16) if isinstance(tx.get("value"), str) else int(tx.get("value", 0))
    data = tx.get("data", "0x")

    factors = []
    details = {"chain": chain["name"], "chain_id": chain_id, "to": to, "to_label": label_address(to)}
    summary = ""
    trusted_spender = False

    # ── Decode transaction type ──

    if data.startswith("0x095ea7b3"):
        approval = decode_approval(data)
        if approval:
            token_name = get_token_name(to)
            details["type"] = "Token Approval"
            details["token"] = to
            details["token_name"] = token_name
            details["spender"] = approval["spender"]
            details["spender_label"] = label_address(approval["spender"])
            details["unlimited"] = approval["unlimited"]
            trusted_spender = is_trusted_address(approval["spender"])
            details["spender_trusted"] = trusted_spender

            if approval["unlimited"]:
                if trusted_spender:
                    summary = f"Grants unlimited {token_name} access to {label_address(approval['spender'])} (trusted protocol). Lower risk, but limited approvals are always safer."
                    details["suggestion"] = "Even trusted protocols are safer with limited approvals."
                else:
                    factors.append({"type": "UNLIMITED_APPROVAL", "detail": f"Unlimited {token_name} approval to unknown address {label_address(approval['spender'])}"})
                    summary = f"Grants UNLIMITED {token_name} spending to {label_address(approval['spender'])}. This address can drain your entire {token_name} balance at any time."
                    details["suggestion"] = "Approve only the amount needed, not unlimited."
            else:
                summary = f"Approves {token_name} spending by {label_address(approval['spender'])}."

    elif data.startswith("0xa22cb465"):
        approval = decode_set_approval_for_all(data)
        if approval and approval["approved"]:
            details["type"] = "NFT Approval (setApprovalForAll)"
            details["operator"] = approval["operator"]
            details["operator_label"] = label_address(approval["operator"])
            trusted_spender = is_trusted_address(approval["operator"])
            details["operator_trusted"] = trusted_spender

            if trusted_spender:
                summary = f"Grants {label_address(approval['operator'])} (trusted marketplace) access to your NFTs."
            else:
                factors.append({"type": "SET_APPROVAL_FOR_ALL", "detail": f"Full NFT access to unknown address {label_address(approval['operator'])}"})
                factors.append({"type": "DRAINER_SIGNATURE", "detail": "setApprovalForAll to unknown operator - high probability of NFT drain"})
                summary = f"DANGER: Grants {label_address(approval['operator'])} permission to transfer ALL your NFTs. #1 NFT phishing method."
                details["suggestion"] = "Only approve for trusted marketplaces (OpenSea, Blur)."
        elif approval:
            details["type"] = "NFT Revoke (setApprovalForAll)"
            summary = "Revokes NFT access. Safe operation."

    elif data == "0x" and value > 0:
        details["type"] = "Native Transfer"
        value_eth = value / 1e18
        details["value_eth"] = round(value_eth, 6)
        summary = f"Sends {value_eth:.6f} ETH to {label_address(to)}."
        if value_eth >= LARGE_ETH_THRESHOLD:
            factors.append({"type": "LARGE_ETH_TRANSFER", "detail": f"Large transfer: {value_eth:.2f} ETH"})

    else:
        func_sig = data[:10] if len(data) >= 10 else data
        sig_info = lookup_function_sig(func_sig)
        details["type"] = "Contract Interaction"
        details["function_sig"] = func_sig
        details["function_name"] = sig_info["name"]
        trusted_spender = is_trusted_address(to)
        details["contract_trusted"] = trusted_spender

        if sig_info["is_drainer"]:
            factors.append({"type": "DRAINER_SIGNATURE", "detail": f"Known drainer function: {sig_info['name']}()"})
            summary = f"DANGER: Calls {sig_info['name']}(), a known drainer function. Do NOT proceed."
        elif trusted_spender:
            summary = f"Calls {sig_info['name']}() on {label_address(to)} (trusted)."
        else:
            summary = f"Calls {sig_info['name']}() on {label_address(to)}."

    # ── Run checks in parallel ──
    checks = run_checks_parallel(to, chain, tx)

    scam = checks.get("scam", {"is_scam": False, "reason": ""})
    age = checks.get("age", {"is_new": False, "age": "unknown"})
    verified = checks.get("verified", {"verified": False, "contract_name": ""})
    balance = checks.get("balance", {"balance_eth": 0, "is_empty": True})
    tx_count = checks.get("tx_count", {"tx_count": 0, "is_new_address": True})
    sim = checks.get("simulation", {"success": False})

    # Scam check
    if scam["is_scam"]:
        factors.append({"type": "SCAM_ADDRESS", "detail": f"Flagged: {scam['reason']}"})
    details["scam_check"] = scam

    # Contract age (skip trusted)
    if age["is_new"] and not trusted_spender:
        factors.append({"type": "CONTRACT_NEW", "detail": f"Contract deployed {age['age']} ago"})
    details["contract_age"] = age["age"]

    # Verification (skip trusted, skip non-contracts)
    if not verified["verified"] and not trusted_spender and age["age"] != "not a contract":
        factors.append({"type": "CONTRACT_UNVERIFIED", "detail": f"Not verified on {chain['name']} explorer"})
        details["verified"] = False
    else:
        details["verified"] = verified["verified"] or trusted_spender
        if verified.get("contract_name"):
            details["contract_name"] = verified["contract_name"]

    # Approval to EOA (skip trusted)
    if not trusted_spender:
        if data.startswith("0x095ea7b3"):
            approval = decode_approval(data)
            if approval and not is_trusted_address(approval["spender"]):
                spender_age = check_contract_age(approval["spender"], chain)
                if spender_age["age"] == "not a contract":
                    factors.append({"type": "NO_CONTRACT_CODE", "detail": "Approval spender is a regular address, not a contract"})
        elif data.startswith("0xa22cb465") and age["age"] == "not a contract":
            factors.append({"type": "NO_CONTRACT_CODE", "detail": "NFT approval targets a regular address"})

    # Suspicious pattern
    susp = check_suspicious_address(to)
    if susp.get("suspicious"):
        factors.append({"type": "SUSPICIOUS_ADDRESS", "detail": susp["reason"]})

    # Empty recipient (skip trusted/known)
    if not trusted_spender and not KNOWN_ADDRESSES.get(to):
        if balance["is_empty"] and tx_count.get("is_new_address") and age["age"] == "not a contract":
            factors.append({"type": "EMPTY_RECIPIENT", "detail": f"Zero balance, {tx_count.get('tx_count', 0)} transactions - possible disposable address"})
    details["recipient_balance_eth"] = balance.get("balance_eth", 0)
    details["recipient_tx_count"] = tx_count.get("tx_count", 0)

    # Honeypot (for transfers, not approvals)
    if data.startswith(("0xa9059cbb", "0x23b872dd")):
        honeypot = check_honeypot_token(to, chain)
        if honeypot.get("is_honeypot"):
            factors.append({"type": "HONEYPOT_TOKEN", "detail": f"Honeypot: {', '.join(honeypot.get('flags', []))}"})
            details["honeypot"] = honeypot

    # Simulation
    if sim.get("success"):
        details["simulation"] = sim

    # Trust note
    if trusted_spender and len(factors) == 0:
        details["trust_note"] = f"{label_address(to)} is a recognized protocol."

    # Score
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
            trusted = is_trusted_address(permit["spender"])
            details["spender_trusted"] = trusted
            amount_str = "ALL" if permit["unlimited"] else permit["amount"]
            summary = f"Authorizes {label_address(permit['spender'])} to transfer {amount_str} {permit['token_name']} without a transaction."
            if permit["unlimited"]:
                factors.append({"type": "UNLIMITED_APPROVAL", "detail": f"Unlimited {permit['token_name']} permit"})
            if not trusted:
                factors.append({"type": "DRAINER_SIGNATURE", "detail": f"Permit spender {label_address(permit['spender'])} is not recognized"})
        else:
            details["type"] = "Typed Data Signature"
            details["primary_type"] = primary_type
            summary = f"Signature on {primary_type} typed data."

    elif method == "eth_sign":
        factors.append({"type": "ETH_SIGN_DANGEROUS", "detail": "eth_sign can authorize ANY wallet action. Most dangerous signature method."})
        details["type"] = "Dangerous Signature (eth_sign)"
        summary = "CRITICAL: eth_sign can drain your entire wallet. Legitimate dApps NEVER use this."

    elif method == "personal_sign":
        details["type"] = "Message Signature"
        summary = "Text message signature. Generally safe."
        message = typed_data if isinstance(typed_data, str) else str(typed_data)
        if message.startswith("0x") and len(message) > 100:
            factors.append({"type": "KNOWN_PHISHING_SIG", "detail": "personal_sign with hex data - possible disguised authorization"})
            summary = "WARNING: Contains hex data that could authorize a transaction."

    score = compute_score(factors)
    level = get_level(score)
    return {
        "score": score, "level": level, "blocked": score > 50,
        "recommendation": "block" if score > 80 else "warn" if score > 20 else "allow",
        "summary": summary, "factors": factors, "details": details,
        "chain": chain["name"], "timestamp": int(time.time())
    }


# ═══════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════

def check_auth():
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if SENTINEL_API_KEY == "dev-key-change-in-production": return True
    return key == SENTINEL_API_KEY


# ═══════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════

@app.route("/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "engine": "sentinel",
        "version": "1.2.0",
        "chains": len(CHAIN_CONFIG),
        "signals": len(RISK_WEIGHTS),
        "trusted_protocols": sum(1 for v in KNOWN_ADDRESSES.values() if v.get("trusted")),
        "checks": [
            "scam_address_detection", "honeypot_token_detection",
            "contract_age_verification", "contract_source_verification",
            "unlimited_approval_detection", "setApprovalForAll_detection",
            "drainer_signature_detection", "suspicious_address_patterns",
            "empty_recipient_detection", "large_transfer_detection",
            "permit_signature_analysis", "eth_sign_detection",
            "function_signature_lookup", "transaction_simulation",
            "recipient_balance_check", "recipient_history_check",
            "trusted_protocol_whitelist", "token_identification",
        ]
    })


@app.route("/v1/chains", methods=["GET"])
def chains():
    return jsonify({"chains": {str(k): v["name"] for k, v in CHAIN_CONFIG.items()}})


@app.route("/v1/score", methods=["POST"])
def score_tx_endpoint():
    if not check_auth(): return jsonify({"error": "Invalid API key"}), 401
    body = request.get_json()
    if not body: return jsonify({"error": "JSON body required"}), 400
    if not body.get("to"): return jsonify({"error": "'to' address required"}), 400
    chain_id = body.get("chainId", body.get("chain_id", 1))
    tx = {"to": body["to"], "from": body.get("from", "0x" + "0" * 40), "data": body.get("data", "0x"), "value": body.get("value", "0x0")}
    start = time.time()
    result = score_transaction(tx, chain_id)
    result["latency_ms"] = int((time.time() - start) * 1000)
    return jsonify(result)


@app.route("/v1/score/signature", methods=["POST"])
def score_sig_endpoint():
    if not check_auth(): return jsonify({"error": "Invalid API key"}), 401
    body = request.get_json()
    if not body: return jsonify({"error": "JSON body required"}), 400
    method = body.get("method", "eth_signTypedData_v4")
    typed_data = body.get("typedData", body.get("typed_data", {}))
    chain_id = body.get("chainId", body.get("chain_id", 1))
    start = time.time()
    result = score_signature(method, typed_data, chain_id)
    result["latency_ms"] = int((time.time() - start) * 1000)
    return jsonify(result)


@app.route("/v1/address/<address>", methods=["GET"])
def check_address_endpoint(address):
    if not check_auth(): return jsonify({"error": "Invalid API key"}), 401
    chain_id = request.args.get("chain_id", 1, type=int)
    chain = get_chain(chain_id)
    checks = run_checks_parallel(address, chain)
    susp = check_suspicious_address(address)
    label = label_address(address)
    return jsonify({
        "address": address, "label": label,
        "known": label != address[:6] + "..." + address[-4:],
        "trusted": is_trusted_address(address),
        "scam": checks.get("scam", {}),
        "suspicious": susp,
        "contract_age": checks.get("age", {}),
        "verified": checks.get("verified", {}),
        "balance_eth": checks.get("balance", {}).get("balance_eth", 0),
        "tx_count": checks.get("tx_count", {}).get("tx_count", 0),
        "chain": chain["name"]
    })


# ═══════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    trusted_count = sum(1 for v in KNOWN_ADDRESSES.values() if v.get("trusted"))
    print(f"""
╔══════════════════════════════════════════════════╗
║   Sentinel Risk Engine API v1.2.0                ║
║   Running on http://localhost:{port}                ║
╠══════════════════════════════════════════════════╣
║   POST /v1/score            Score a tx           ║
║   POST /v1/score/signature  Score a sig          ║
║   GET  /v1/address/:addr    Check address        ║
║   GET  /v1/health           Health check         ║
║   GET  /v1/chains           List chains          ║
╠══════════════════════════════════════════════════╣
║   18 checks | 8 chains | {trusted_count} trusted protocols     ║
╚══════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=True)
