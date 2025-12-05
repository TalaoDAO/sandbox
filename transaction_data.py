import json
import base64
from typing import Optional
from urllib.parse import quote

def _strip_0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s

def _pad32(hex_no_0x: str) -> str:
    return hex_no_0x.rjust(64, "0")

def _encode_erc20_transfer_calldata(recipient: str, amount_base_units: int) -> str:
    """
    Builds 'transfer(address,uint256)' calldata.
    Function selector is 0xa9059cbb (keccak256('transfer(address,uint256)')[:4]).
    """
    selector = "0xa9059cbb"  # as per ERC-20 standard
    # address: 32-byte left-padded (no 0x, lowercase)
    addr_padded = _pad32(_strip_0x(recipient).lower())
    # amount: 32-byte left-padded hex (no 0x)
    amt_padded  = _pad32(hex(amount_base_units)[2:])
    return selector + addr_padded + amt_padded

def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_no_pad_decode(s: str) -> bytes:
    # Add back the missing padding if needed
    padding_needed = (4 - len(s) % 4) % 4
    s += "=" * padding_needed
    return base64.urlsafe_b64decode(s)

def build_evm_erc20_transfer_transaction_data(
    token_symbol: str,
    token_address: str,
    token_decimals: int,
    chain_id: int,  # 1 = Ethereum mainnet
    recipient: str,
    human_amount: str,
    credential_ids: Optional[list] = None,
    order_id: Optional[str] = None,
    title: Optional[str] = None,
    subtitle: Optional[str] = None,
    icon_uri: Optional[str] = None,
    purpose: Optional[str] = None
) -> dict:
   
    if credential_ids is None:
        credential_ids = ["pid_credential"]  # use your PD/DCQL id(s) here

    # Convert human_amount (e.g., "12.345") -> base units int
    # Avoid float; split by dot and scale.
    parts = human_amount.split(".")
    if len(parts) == 1:
        int_part, frac_part = parts[0], "0"
    elif len(parts) == 2:
        int_part, frac_part = parts
    else:
        raise ValueError("Invalid amount format")

    if len(frac_part) > token_decimals:
        raise ValueError(f"Too many decimal places for token with {token_decimals} decimals")

    frac_part = (frac_part + "0" * token_decimals)[:token_decimals]
    amount_base_units = int(int_part) * (10 ** token_decimals) + (int(frac_part) if frac_part else 0)

    calldata = _encode_erc20_transfer_calldata(recipient, amount_base_units)

    tx_obj = {
        "type": "evm.erc20_transfer",  # profile alias for an ERC-20 transfer via eth_sendTransaction
        "credential_ids": credential_ids,
        "chain_id": chain_id,
        "asset": {
            "symbol": token_symbol,
            "address": token_address,
            "decimals": token_decimals
        },
        "amount": str(amount_base_units),         # display/validation only (source of truth is rpc.data)
        "recipient": recipient,                   # display/validation only
        "rpc": {
            "method": "eth_sendTransaction",
            "params": [{
                "to": token_address,             # ERC-20 contract
                "value": "0x0",
                "data": calldata,
                # Optionally add gas fields:
                # "gas": "0x186a0",
                # "maxFeePerGas": "0x59682f00",
                # "maxPriorityFeePerGas": "0x3b9aca00",
            }]
        }
    }

    if order_id:
        tx_obj["order_id"] = order_id
    if title or subtitle or icon_uri or purpose:
        tx_obj["ui_hints"] = {}
        if title: tx_obj["ui_hints"]["title"] = title
        if subtitle: tx_obj["ui_hints"]["subtitle"] = subtitle
        if icon_uri: tx_obj["ui_hints"]["icon_uri"] = icon_uri
        if purpose: tx_obj["ui_hints"]["purpose"] = purpose

    # Optional EIP-681 deep link for wallets that support it
    # ethereum:<token_address>@<chain_id>/transfer?address=<recipient>&uint256=<amount_base_units>
    tx_obj["eip681"] = (
        f"ethereum:{token_address}@{chain_id}/transfer"
        f"?address={recipient}&uint256={amount_base_units}"
    )

    encoded = _b64url_no_pad(json.dumps(tx_obj, separators=(",", ":")).encode("utf-8"))
    authorization_details = quote(json.dumps(tx_obj, separators=(",", ":")).encode("utf-8"))
    return {
        "authorization_detail": authorization_details,
        "decoded": tx_obj,
        "base64url": encoded
    }


if __name__ == '__main__':
    out = build_evm_erc20_transfer_transaction_data(
        "USDC",
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        6,
        1,
        "0x03817255659dc455079df516c5271b4046b2065b",  # wallet account to transfer
        "10.0",  # USDC token
        credential_ids = ["pid_credential"],
        #order_id = "#16805",
        #title = "Crypto paiement",
        #subtitle = "This is a test for an ERC20 transfer",
        icon_uri="https://talao.co/server/image/pizza.jpeg",
        purpose="Pay to Pizza Shop"
    )

    print(json.dumps(out, indent=4))
    
    
    out = build_evm_erc20_transfer_transaction_data(
        "USDT",
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        6,
        1,
        "0x03817255659dc455079df516c5271b4046b2065b",  # wallet account to transfer
        "95.0",  # 95 USD
        credential_ids = ["over18"],
        icon_uri="https://talao.co/server/image/whisky.png",
        purpose="Buy The Yamazaki - Distiller's Reserve "
    )

    print(json.dumps(out, indent=4))