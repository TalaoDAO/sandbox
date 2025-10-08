# crypto_transfer.py
from flask import request, render_template, redirect, flash
import json
from Crypto.Hash import keccak  # pip install pycryptodome

from transaction_data import (
    build_evm_erc20_transfer_transaction_data as build_tx
)

# ---------------------------------------------------------------------
# Token registry (contract + decimals) — user picks ONLY the symbol.
# Chain IDs: 1 = mainnet, 11155111 = sepolia
# ---------------------------------------------------------------------
TOKENS = {
    "USDC": {
        1:         {"address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "decimals": 6},
        11155111:  {"address": "0x254d06f33bdc5b8ee05b2ea472107e300226659a", "decimals": 6},  # Circle test token
    },
    "USDT": {
        1:         {"address": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "decimals": 6},
        # (no canonical Sepolia at time of writing)
    },
    "TALAO": {
        1:         {"address": "0x1D4cCC31dAB6EA20f461d329a0562C1c58412515", "decimals": 18},
        # add test deployment here if available
    },
}

def _lookup_token(symbol: str, chain_id: int):
    meta = TOKENS.get(symbol)
    if not meta:
        raise ValueError(f"Unsupported token symbol: {symbol}")
    chain_meta = meta.get(chain_id)
    if not chain_meta:
        raise ValueError(f"{symbol} is not configured on chain_id {chain_id}")
    return chain_meta["address"], chain_meta["decimals"]

# ---------------------------------------------------------------------
# Public entry point used by main.py
# main.py ⇒
#   import crypto_transfer
#   crypto_transfer.init_app(app, red, mode)
# ---------------------------------------------------------------------

def init_app(app, red, mode):
    app.add_url_rule('/crypto_transfer',  view_func=_form, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/crypto_transfer', view_func= _form,  methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/crypto_transfer/build', view_func=_build_and_launch, methods=['POST'], defaults={'mode': mode})


def _form(mode):
    return render_template(
        'crypto_transfer.html',
        company_name='Web3IDPay',
        page_background_color='#ffffff',
        page_text_color='#111827',
        page_title='EUDI Wallet — ERC-20 Transfer',
        page_subtitle='Compose authorization_details and call Talao sandbox (OIDC4VP)',
        use_sepolia=False,
        decoded_json='',
        launch_url=''
    )

def _build_and_launch(mode):
    # Read minimal inputs
    token_symbol = (request.form.get('token_symbol') or '').strip().upper()
    chain_id = 11155111 if request.form.get('use_sepolia') else 1
    recipient = (request.form.get('recipient') or '').strip()
    human_amount = (request.form.get('human_amount') or '').strip()

    # Optional UI fields
    order_id    = request.form.get('order_id') or None
    ui_title    = request.form.get('ui_title') or None
    ui_subtitle = request.form.get('ui_subtitle') or None
    ui_icon_uri = request.form.get('ui_icon_uri') or None
    ui_purpose  = request.form.get('ui_purpose') or None
    
    if chain_id == 11155111 and token_symbol in["USDT", "TALAO"]:
        flash("Token not supported on Sepolia", "warning")
        return redirect('/crypto_transfer')
    
    if not is_valid_eth_address(recipient, require_checksum=False):
        flash("Not a valid ethereum address", "warning")
        return redirect('/crypto_transfer')


    try:
        token_address, token_decimals = _lookup_token(token_symbol, chain_id)

        out = build_tx(
            token_symbol=token_symbol,
            token_address=token_address,
            token_decimals=token_decimals,
            chain_id=chain_id,
            recipient=recipient,
            human_amount=human_amount,
            credential_ids=["pid_credential"],
            order_id=order_id,
            title=ui_title,
            subtitle=ui_subtitle,
            icon_uri=ui_icon_uri,
            purpose=ui_purpose
        )
    except Exception as e:
        # Re-render the form with the error
        return render_template(
            'crypto_transfer.html',
            company_name='Web3IDPay',
            page_background_color='#ffffff',
            page_text_color='#111827',
            page_title='EUDI Wallet — ERC-20 Transfer',
            page_subtitle='Compose authorization_details and call Talao sandbox (OIDC4VP)',
            use_sepolia=(chain_id == 11155111),
            decoded_json=f'Error: {str(e)}',
            launch_url=''
        ), 400

    authorization_details = out["authorization_detail"]

    # Use same client_id/redirect pattern as test 14
    # (see test_verifier_oidc4vc.py verifier_test_14)  # client ids differ by env
    if mode.myenv == 'aws':
        client_id = "cfjiehhlkn"
    else:
        client_id = "frrrgvvtdt"

    launch_url = (
        mode.server +
        "sandbox/verifier/app/authorize?client_id=" + client_id +
        "&authorization_details=" + authorization_details +
        "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" +
        mode.server + "sandbox/verifier/callback3"
    )

    # Immediate redirect (like tests). If you’d rather inspect first, flip to rendering.
    return redirect(launch_url)


import re

# Basic 0x + 40 hex
_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

def is_checksum_address(addr: str) -> bool:
    """
    Strict EIP-55 checksum check.
    Tries eth_utils first, then falls back to Keccak via pycryptodome if available.
    """
    if not isinstance(addr, str) or not _ADDR_RE.fullmatch(addr):
        return False

    # Prefer eth_utils if installed
    try:
        from eth_utils import is_checksum_address as _eth_is_checksum_address
        return _eth_is_checksum_address(addr)
    except Exception:
        pass

    # Fallback: manual EIP-55 via Keccak-256 (pycryptodome)
    try:
        addr_noprefix = addr[2:]
        lower = addr_noprefix.lower()
        k = keccak.new(digest_bits=256)
        k.update(lower.encode("ascii"))
        hash_hex = k.hexdigest()
        for i, ch in enumerate(addr_noprefix):
            if ch.isalpha():
                # nibble >= 8 => uppercase, else lowercase
                want_upper = int(hash_hex[i], 16) >= 8
                if want_upper != ch.isupper():
                    return False
        return True
    except Exception:
        # If we can't compute Keccak, we cannot verify mixed-case safely
        # Only accept addresses that are entirely lower or upper as "non-checksummed".
        return addr == addr.lower() or addr == addr.upper()

def is_valid_eth_address(addr: str, require_checksum: bool = False) -> bool:
    """
    - If require_checksum=False (default): accept
        * exact EIP-55 checksummed OR
        * all-lowercase OR all-uppercase (non-checksummed but well-formed).
    - If require_checksum=True: only accept strict EIP-55.
    """
    if not isinstance(addr, str) or not _ADDR_RE.fullmatch(addr):
        return False

    if require_checksum:
        return is_checksum_address(addr)

    # Accept checksummed OR uniform case
    return (
        addr == addr.lower()
        or addr == addr.upper()
        or is_checksum_address(addr)
    )
