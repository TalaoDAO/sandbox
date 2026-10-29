"""Scope, source coverage and size regression checks for wallet prompts."""
import json

import pytest
import tiktoken

from test_ai_wallet import metadata as metadata_fixture

from ai import normative_context as context
from ai import ai_agent_for_vc as vc, ai_agent_for_qrcode as qr
from ai.wallet_validation import InputError

enc = tiktoken.get_encoding('o200k_base')


@pytest.fixture
def metadata():
    return metadata_fixture.__wrapped__()


def test_sdjwt_context_core_and_budget():
    text = context.sd_jwt('13', {'typ':'dc+sd-jwt'}, {'vct':'urn:pid'}, {}, False)
    assert len(enc.encode(text)) < 14000
    for required in ('JOSE Header','JWT Claims Set','Issuer Signature Mechanisms','Disclosures','Verification of the SD-JWT'):
        assert required in text
    assert 'Source: dataset/tsl/' not in text
    assert 'section 4.3:' not in text # no KB JWT
    assert 'section 5:' not in context.excerpts('sdjwt/rfc9901.txt',numbers=('4.1','4.2','7.1'))
    assert '### Source:' in text


def test_sdjwt_kb_status_and_type_selected_only_when_used():
    text = context.sd_jwt('13', {}, {'status': {'status_list':{}}, 'vct#integrity':'sha256-test'}, {'claims':[]}, True)
    for required in ('Source: dataset/tsl/12.txt', 'Key Binding JWT','Document Integrity','Claim Metadata','Type Metadata Format'):
        assert required in text
    assert len(enc.encode(text)) < 24000


@pytest.mark.parametrize('draft',['7','8','9','10','11','12','13'])
def test_sdjwt_source_version_preserved(draft):
    text = context.sd_jwt(draft,{}, {},{},False)
    assert f'Source: dataset/sdjwtvc/{draft}.txt' in text


@pytest.mark.parametrize('draft',['11','12','13','14','15','16','17','18','1.0'])
def test_issuer_reference_versions(metadata, draft):
    offer,meta,auth=metadata
    text=context.issuer(draft,offer,meta,'')
    assert f'Source: dataset/oidc4vci/{draft}.md' in text
    assert 'Credential Issuer Metadata' in text
    assert 'Source: dataset/haip/1.0.md' in text
    assert len(enc.encode(text)) < 23000


def test_issuer_format_and_scope_selection(metadata):
    offer,meta,auth=metadata
    text=context.issuer('1.0',offer,meta,'')
    assert 'section A.3: IETF SD-JWT VC' in text
    assert 'section A.2:' not in text
    assert 'section A.2.2:' not in text
    assert 'section 5:' not in context.excerpts('haip/1.0.md',numbers=('4','7','8'))
    assert 'Informative References' not in text
    meta['credential_configurations_supported']['pid']={'format':'mso_mdoc','doctype':'org.iso.18013.5.1.mDL'}
    text=context.issuer('1.0',offer,meta,'')
    assert 'Mobile Documents or mdocs' in text
    assert 'section A.3:' not in text
    assert 'section A.3.2:' not in text


def test_display_bulk_not_sent_to_gpt(metadata):
    offer,meta,auth=metadata
    meta['display']=[{'logo':{'uri':'data:image/png;base64,'+'a'*100000}}]
    meta['credential_configurations_supported']['unoffered']={'format':'mso_mdoc','display':[{'name':'not offered'}]}
    projected=context.issuer_prompt_metadata(meta,offer)
    assert len(json.dumps(projected)) < 2000
    assert 'display' not in projected
    assert list(projected['credential_configurations_supported'])==['pid']
    assert projected['_diagnostic_other_configuration_count']==1
    assert 'display' in meta # source metadata remains complete for deterministic validation


@pytest.mark.parametrize('draft',['18','20','28','30'])
def test_verifier_context_selection(draft):
    text=context.verifier(draft,{'dcql_query':{'credentials':[]},'response_mode':'direct_post.jwt'},'HAIP',None,False)
    assert 'Authorization Request' in text
    assert 'Source: dataset/haip/1.0.md' in text
    assert len(enc.encode(text))<25000
    if draft=='30':
        assert 'Digital Credentials Query Language' in text
        assert 'Encrypted Responses' in text


def test_missing_source_never_falls_back_to_whole_document():
    with pytest.raises(InputError): context.sd_jwt('2',{}, {},{},False)
    with pytest.raises(InputError): context.excerpts('sdjwtvc/13.txt',titles=('no such section',))
    with pytest.raises(InputError): context.pack('x'*(context.MAX_CONTEXT_CHARS+1))


def test_wallet_pro_model_and_attribution():
    for agent in (vc,qr):
        assert agent.openai_model_pro.model_name=='gpt-6.1-sol'
        assert agent.openai_model_pro.reasoning_effort=='medium'
        assert agent.engine('pro','openai')=='gpt-6.1-sol'
        assert agent.engine('flash','openai')=='gpt-4o-mini'
        assert agent.engine('escalation','openai')=='gpt-5-mini'
