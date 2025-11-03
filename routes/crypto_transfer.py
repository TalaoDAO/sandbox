from flask import request, render_template, redirect, flash
import json
from Crypto.Hash import keccak  # pip install pycryptodome
import re

from transaction_data import (
    build_evm_erc20_transfer_transaction_data as build_tx
)

# ------------------------------
# Networks
# ------------------------------
EVM = 'evm'
TEZOS = 'tezos'

NETWORKS = {
    'ethereum:mainnet': { 'type': EVM,   'chain_id': 1 },
    'ethereum:sepolia': { 'type': EVM,   'chain_id': 11155111 },
    'polygon:mainnet':  { 'type': EVM,   'chain_id': 137 },
    'polygon:amoy':     { 'type': EVM,   'chain_id': 80002 },
    'etherlink:mainnet':{ 'type': EVM,   'chain_id': 42793 },
    'etherlink:testnet':{ 'type': EVM,   'chain_id': 128123 },
    'tezos:mainnet':    { 'type': TEZOS, 'network': 'mainnet' },
    'tezos:ghostnet':   { 'type': TEZOS, 'network': 'ghostnet' },
}

# ------------------------------
# Token registry per network
# Only ERC-20 tokens on EVM are actionable in this demo.
# ------------------------------
TOKENS = {
    # Ethereum
    'ethereum:mainnet': {
        # Verified: USDC (Circle) mainnet
        'USDC':  { 'kind': 'erc20', 'address': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'decimals': 6 },  # :contentReference[oaicite:0]{index=0}
        # Verified: USDT mainnet
        'USDT':  { 'kind': 'erc20', 'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7', 'decimals': 6 },  # :contentReference[oaicite:1]{index=1}
        # As requested: TALAO on Ethereum mainnet
        'TALAO': { 'kind': 'erc20', 'address': '0x1D4cCC31dAB6EA20f461d329a0562C1c58412515', 'decimals': 18 },
        # Native coin (not built by this demo)
        'ETH':   { 'kind': 'native' }
    },
    'ethereum:sepolia': {
        # Verified: Circle USDC (Sepolia)
        'USDC':  { 'kind': 'erc20', 'address': '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238', 'decimals': 6 },  # :contentReference[oaicite:2]{index=2}
        'EURC':  { 'kind': 'erc20', 'address': '0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4', 'decimals': 6 },  # :contentReference[oaicite:2]{index=2}
     
        'ETH':   { 'kind': 'native' }
    },

    # Polygon PoS
    'polygon:mainnet': {
        # Native USDC (not USDC.e)
        'USDC':  { 'kind': 'erc20', 'address': '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', 'decimals': 6 },  # :contentReference[oaicite:3]{index=3}
        # USDT on Polygon PoS
        'USDT':  { 'kind': 'erc20', 'address': '0xc2132D05D31c914A87C6611C10748AEb04B58e8F', 'decimals': 6 },  # :contentReference[oaicite:4]{index=4}
        'MATIC': { 'kind': 'native' }
    },
    'polygon:amoy': {
        # USDC on Amoy testnet
        'USDC':  { 'kind': 'erc20', 'address': '0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582', 'decimals': 6 },  # :contentReference[oaicite:5]{index=5}
        'MATIC': { 'kind': 'native' }
    },

    # Etherlink (native XTZ on an EVM L2)
    'etherlink:mainnet': {
        # Etherlink native is XTZ; WXTZ exists as ERC-20 but we don’t assume an address here.
        'XTZ':   { 'kind': 'native' }  # :contentReference[oaicite:6]{index=6}
    },
    'etherlink:testnet': {
        'XTZ':   { 'kind': 'native' }  # :contentReference[oaicite:7]{index=7}
    },

    # Tezos
    'tezos:mainnet': {
        'XTZ':   { 'kind': 'native' },  # Tezos native
        # USDT does exist on Tezos (FA1.2/FA2), but this demo doesn’t build Tezos tx yet.
    },
    'tezos:ghostnet': {
        'XTZ':   { 'kind': 'native' },
    }
}

def _lookup_token(network_key: str, symbol: str):
    net = TOKENS.get(network_key) or {}
    meta = net.get(symbol)
    if not meta:
        raise ValueError(f"{symbol} is not configured on {network_key}")
    return meta

# ------------------------------
# Public entry points
# ------------------------------
def init_app(app, red, mode):
    app.add_url_rule('/crypto_transfer',  view_func=_form, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/crypto_transfer', view_func=_form,  methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/crypto_transfer/build', view_func=_build_and_launch, methods=['POST'], defaults={'mode': mode})

def _form(mode):
    return render_template(
        'crypto_transfer.html',
        company_name='Web3IDPay',
        decoded_json='',
        launch_url=''
    )

def _build_and_launch(mode):
    network_key   = (request.form.get('network_key') or '').strip()
    chain_type    = (request.form.get('chain_type') or '').strip()
    token_symbol  = (request.form.get('token_symbol') or '').strip().upper()
    token_kind    = (request.form.get('token_kind') or '').strip()
    recipient     = (request.form.get('recipient') or '').strip()
    human_amount  = (request.form.get('human_amount') or '').strip()
    draft         = 23 if request.form.get('above_23') else 20

    # Optional UI fields
    order_id    = request.form.get('order_id') or None
    ui_title    = request.form.get('ui_title') or None
    ui_subtitle = request.form.get('ui_subtitle') or None
    ui_icon_uri = request.form.get('ui_icon_uri') or None
    ui_purpose  = request.form.get('ui_purpose') or None

    # Validate network
    net_cfg = NETWORKS.get(network_key)
    if not net_cfg:
        flash("Unsupported network", "warning")
        return redirect('/crypto_transfer')

    # Recipient validation by chain type
    if chain_type == EVM:
        if not is_valid_eth_address(recipient, require_checksum=False):
            flash("Not a valid EVM address (expected 0x…)", "warning")
            return redirect('/crypto_transfer')
    elif chain_type == TEZOS:
        if not is_valid_tezos_address(recipient):
            flash("Not a valid Tezos address (tz1… / tz2… / tz3… / KT1…)", "warning")
            return redirect('/crypto_transfer')
    else:
        flash("Unknown chain type", "warning")
        return redirect('/crypto_transfer')

    # Lookup token meta for the selected network
    try:
        token_meta = _lookup_token(network_key, token_symbol)
    except Exception as e:
        return render_template('crypto_transfer.html', decoded_json=f'Error: {str(e)}', launch_url=''), 400

    # For this demo we only build EVM ERC-20 transfers
    if chain_type != EVM:
        flash("Tezos networks are shown in the UI, but this demo currently builds only EVM ERC-20 transfers.", "warning")
        return redirect('/crypto_transfer')

    if token_meta.get('kind') != 'erc20':
        flash("Native-coin transfers are not built by this demo yet. Please choose a stablecoin/ERC-20.", "warning")
        return redirect('/crypto_transfer')

    chain_id = int(request.form.get('chain_id') or net_cfg.get('chain_id') or 0)

    # Build EVM ERC-20 transfer
    try:
        out = build_tx(
            token_symbol=token_symbol,
            token_address=token_meta['address'],
            token_decimals=token_meta['decimals'],
            chain_id=chain_id,
            recipient=recipient,
            human_amount=human_amount,
            credential_ids=["pid_credential"],
            #order_id=order_id,
            #title=ui_title,
            #subtitle=ui_subtitle,
            icon_uri=ui_icon_uri,
            purpose=ui_purpose
        )
    except Exception as e:
        return render_template('crypto_transfer.html',
                               decoded_json=f'Error: {str(e)}',
                               launch_url=''), 400

    authorization_details = out["authorization_detail"]

    # Pick client_id by OIDC4VP draft + env (kept from your code)
    if draft == 20:
        client_id = "mnpqhqqrlw" if mode.myenv == 'aws' else "nyudzjxuhj"
    else:
        client_id = "cfjiehhlkn" if mode.myenv == 'aws' else "frrrgvvtdt"

    launch_url = (
        mode.server +
        "sandbox/verifier/app/authorize?client_id=" + client_id +
        "&authorization_details=" + authorization_details +
        "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" +
        mode.server + "sandbox/verifier/callback3"
    )
    return redirect(launch_url)

# ------------------------------
# Address validation helpers
# ------------------------------

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

def is_checksum_address(addr: str) -> bool:
    if not isinstance(addr, str) or not _ADDR_RE.fullmatch(addr):
        return False
    try:
        from eth_utils import is_checksum_address as _eth_is_checksum_address
        return _eth_is_checksum_address(addr)
    except Exception:
        pass
    try:
        addr_noprefix = addr[2:]
        lower = addr_noprefix.lower()
        k = keccak.new(digest_bits=256); k.update(lower.encode("ascii"))
        hash_hex = k.hexdigest()
        for i, ch in enumerate(addr_noprefix):
            if ch.isalpha():
                want_upper = int(hash_hex[i], 16) >= 8
                if want_upper != ch.isupper():
                    return False
        return True
    except Exception:
        return addr == addr.lower() or addr == addr.upper()

def is_valid_eth_address(addr: str, require_checksum: bool = False) -> bool:
    if not isinstance(addr, str) or not _ADDR_RE.fullmatch(addr):
        return False
    if require_checksum:
        return is_checksum_address(addr)
    return (addr == addr.lower() or addr == addr.upper() or is_checksum_address(addr))

# Very lightweight Tezos address check (base58 structure is stricter; this is enough for UI validation)
_TZ_PREFIXES = ("tz1", "tz2", "tz3", "KT1")
def is_valid_tezos_address(addr: str) -> bool:
    return isinstance(addr, str) and any(addr.startswith(p) for p in _TZ_PREFIXES) and len(addr) >= 36
