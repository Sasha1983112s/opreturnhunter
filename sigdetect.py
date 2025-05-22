"""
SigDetect: Обнаружение нестандартных подписей и форматов входящих транзакций.
"""

import requests
import argparse

def get_transactions(address):
    url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}"
    r = requests.get(url)
    if r.status_code != 200:
        raise Exception("Ошибка получения транзакций")
    return r.json()["data"][address]["transactions"]

def get_transaction_outputs(txid):
    url = f"https://api.blockchair.com/bitcoin/raw/transaction/{txid}"
    r = requests.get(url)
    if r.status_code != 200:
        return []
    try:
        return r.json()["data"][txid]["decoded_raw_transaction"]["vout"]
    except:
        return []

def classify_script(script_hex):
    if script_hex.startswith("a9"):  # OP_HASH160
        return "P2SH"
    elif script_hex.startswith("76"):  # OP_DUP
        return "P2PKH"
    elif script_hex.startswith("00"):  # SegWit
        return "P2WPKH / P2WSH"
    elif script_hex.startswith("51") or script_hex.startswith("52"):
        return "Multisig"
    elif script_hex.startswith("0014") or script_hex.startswith("0020"):
        return "SegWit v0"
    elif script_hex.startswith("5120"):
        return "Taproot"
    return "Unknown"

def analyze_signatures(address):
    print(f"🔍 Анализ типов выходов, направленных на адрес: {address}")
    txs = get_transactions(address)
    results = {}

    for txid in txs[:30]:
        vouts = get_transaction_outputs(txid)
        for v in vouts:
            value = float(v.get("value", 0))
            script_hex = v.get("script_hex", "")
            addresses = v.get("script_pub_key", {}).get("addresses", [])
            if address in addresses:
                script_type = classify_script(script_hex)
                results.setdefault(script_type, 0)
                results[script_type] += value

    if not results:
        print("Нет данных о типах подписей для анализа.")
    else:
        print("📌 Типы выходов и полученные суммы:")
        for t, v in results.items():
            print(f"  - {t}: {v:.8f} BTC")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SigDetect — определяет формат входов и выходов по сигнатурам.")
    parser.add_argument("address", help="Bitcoin-адрес")
    args = parser.parse_args()
    analyze_signatures(args.address)
