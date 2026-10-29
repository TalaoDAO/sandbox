"""Deterministic, source-preserving selection of local normative excerpts.
No embeddings, remote retrieval, LLM summaries or silent whole-document fallback.
Sections retain their source/version; examples and unrelated flows are excluded.
"""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re

from ai.wallet_validation import InputError

DATASET = Path(__file__).resolve().parents[1] / 'dataset'
MAX_CONTEXT_CHARS = 100_000

@dataclass(frozen=True)
class Section:
    key: str
    title: str
    level: int
    ancestors: tuple
    text: str

@lru_cache(maxsize=64)
def _sections(relative, modified, size):
    path = (DATASET / relative).resolve()
    if not path.is_relative_to(DATASET.resolve()):
        raise InputError('Invalid normative source path')
    text = path.read_text(encoding='utf-8-sig')
    lines = text.splitlines()
    headings = []
    markdown = bool(re.search(r'^#{1,5} \S', text, re.M))
    for i, line in enumerate(lines):
        if markdown:
            match = re.match(r'^(#{1,6})\s+(.+)', line)
            if match:
                title = re.sub(r'\s*\{#[^}]+\}', '', match[2]).strip()
                headings.append((i, title, len(match[1]), title))
        else:
            match = re.match(r'^((?:[0-9]+|[A-Z])\.(?:[0-9]+\.)*)\s{2,}(\S.*)$', line)
            if match:
                headings.append((i, match[1].rstrip('.'), match[1].count('.'), match[2]))
            elif re.fullmatch(r'Appendix [A-Z]\.', line) and i+1 < len(lines):
                headings.append((i, line.split()[1].rstrip('.'), 1, lines[i+1]))
            elif re.fullmatch(r'(?:[0-9]+|[A-Z])\.(?:[0-9]+\.)*', line) and i+1 < len(lines) and re.match('[A-Za-z]', lines[i+1]):
                headings.append((i, line.rstrip('.'), line.count('.'), lines[i+1]))
    if not headings:
        raise InputError(f'No normative section boundaries found in {relative}')
    result, stack = [], []
    for n, (start, key, level, title) in enumerate(headings):
        while stack and stack[-1][0] >= level:
            stack.pop()
        end = headings[n+1][0] if n+1 < len(headings) else len(lines)
        body = '\n'.join(lines[start:end]).strip()
        # Remove repeated RFC pagination only, without rewriting normative prose.
        body = re.sub(r'^.*\[Page [0-9]+\].*$', '', body, flags=re.M)
        result.append(Section(key, title, level, tuple(v[1] for v in stack), body))
        stack.append((level, key))
    return tuple(result)


def excerpts(relative, *, numbers=(), titles=()):
    """Select complete sections and descendants; never cut a normative paragraph."""
    path = DATASET / relative
    if not path.is_file():
        raise InputError(f'Normative source unavailable: {relative}')
    stat = path.stat()
    sections = _sections(relative, stat.st_mtime_ns, stat.st_size)
    selected = set()
    for sec in sections:
        if sec.key in numbers or any(re.search(pattern, sec.title, re.I) for pattern in titles):
            selected.add(sec.key)
    if not selected:
        raise InputError(f'Required normative sections unavailable: {relative}')
    pieces = []
    for sec in sections:
        # Example-only subtrees, appendices of samples and bibliographies are not rules.
        lineage = [s for s in sections if s.key in sec.ancestors] + [sec]
        if any(re.search(r'\bexamples?\b|document history|acknowledg|references|notices', s.title, re.I) for s in lineage):
            continue
        if sec.key in selected or selected.intersection(sec.ancestors):
            pieces.append(f'### Source: dataset/{relative} — section {sec.key}: {sec.title}\n{sec.text}')
    if not pieces:
        raise InputError(f'No applicable normative excerpts: {relative}')
    return '\n\n'.join(pieces)


def pack(*parts):
    result = ('Selected local normative excerpts only. Unincluded sections are outside this diagnostic scope; '
              'do not infer requirements or certification from absent text. Deterministic findings are authoritative.\n\n'
              + '\n\n'.join(p for p in parts if p))
    if len(result) > MAX_CONTEXT_CHARS:
        raise InputError('Selected normative context exceeds diagnostic budget; refine the selection')
    return result


def sd_jwt(draft, header, payload, type_metadata, has_kb):
    if not str(draft).isdigit() or not 1 <= int(draft) <= 13:
        raise InputError('Unsupported SD-JWT VC draft')
    path = f'sdjwtvc/{draft}.txt'
    # Titles preserve numbering differences between supported historical drafts.
    vc_titles = [r'^Verifiable Credentials based on SD-JWT$', r'^Verification and Processing$', r'^Issuer Signature Mechanisms$']
    if not header.get('x5c'):
        vc_titles.append(r'^JWT VC Issuer Metadata$')
    if has_kb:
        vc_titles.extend([r'^Presenting Verifiable Credentials$', r'^Key Binding JWT$'])
    if type_metadata:
        vc_titles.extend([r'^Type Metadata Format$', r'^Claim Metadata$'])
    if payload.get('vct#integrity'):
        vc_titles.append(r'^Document Integrity$')
    core = ['4.1', '4.2', '7.1', '9.11']
    if has_kb:
        core += ['4.3', '7.3', '9.5']
    status = excerpts('tsl/12.txt', numbers=('6.1', '6.2', '8.3', '11.3')) if payload.get('status') else ''
    return pack(excerpts(path, titles=vc_titles), excerpts('sdjwt/rfc9901.txt', numbers=core), status)


def issuer(draft, offer, metadata, profile):
    draft = str(draft)
    if draft != '1.0' and draft not in {str(i) for i in range(11, 19)}:
        raise InputError('Unsupported OIDC4VCI version')
    titles = [r'^Credential Offer Parameters$', r'^Sending Credential Offer',
              r'^Metadata$',
              r'^Trust between Wallet and Issuer$', r'^TLS Requirements$']
    formats = {c.get('format') for c in metadata.get('credential_configurations_supported', {}).values() if isinstance(c, dict)}
    if formats.intersection({'dc+sd-jwt', 'vc+sd-jwt'}):
        titles.append(r'^IETF SD-JWT VC$')
    if 'mso_mdoc' in formats:
        titles.append(r'^Mobile Documents or mdocs')
    if 'authorization_code' in offer.get('grants', {}):
        titles += [r'^Pushed Authorization Request$', r'^Using.*scope.*Request Issuance']
    haip = excerpts('haip/1.0.md', numbers=('4', '7', '8'))
    profile_text = excerpts('diip/4.md', titles=(r'.*',)) if profile == 'DIIP_V4' else ''
    return pack(excerpts(f'oidc4vci/{draft}.md', titles=titles), haip, profile_text)


def verifier(draft, request, profile, transaction_data, ts12):
    if str(draft) not in {str(i) for i in range(18, 31)}:
        raise InputError('Unsupported OIDC4VP draft')
    titles = [r'^Authorization Request$', r'^Verifier Metadata', r'^Client Metadata',
              r'^Response Parameters$', r'^VP Token Validation$', r'^Client Identifier',
              r'^Response Mode.*direct_post']
    if request.get('dcql_query'):
        titles += [r'^Digital Credentials Query Language', r'^Claims Path Pointer$']
    elif request.get('presentation_definition') or request.get('presentation_definition_uri'):
        titles += [r'presentation definition', r'presentation exchange']
    if request.get('response_mode', '').endswith('.jwt'):
        titles.append(r'^Encrypted Responses$')
    if transaction_data:
        titles.append(r'^Transaction Data$')
    extra = []
    if profile == 'HAIP':
        extra.append(excerpts('haip/1.0.md', numbers=('5', '7', '8')))
    if profile == 'DIIP_V4':
        extra.append(excerpts('diip/4.md', titles=(r'.*',)))
    if ts12:
        extra.append(excerpts('ts/ts12.md', titles=(r'.*',)))
    return pack(excerpts(f'oidc4vp/{draft}.md', titles=titles), *extra)


def issuer_prompt_metadata(metadata, offer):
    """Keep protocol evidence; discard translated display/assets and other offers' bulk."""
    result = {k: v for k, v in metadata.items() if k not in ('display', 'signed_metadata')}
    configs = metadata.get('credential_configurations_supported', {})
    offered = offer.get('credential_configuration_ids', [])
    result['credential_configurations_supported'] = {}
    for cid in offered:
        cfg = configs.get(cid)
        if not isinstance(cfg, dict):
            continue
        cfg = {k: v for k, v in cfg.items() if k != 'display'}
        if isinstance(cfg.get('credential_metadata'), dict):
            cfg['credential_metadata'] = {k: v for k, v in cfg['credential_metadata'].items() if k != 'display'}
        result['credential_configurations_supported'][cid] = cfg
    if len(configs) > len(result['credential_configurations_supported']):
        result['_diagnostic_other_configuration_count'] = len(configs) - len(result['credential_configurations_supported'])
    return result
