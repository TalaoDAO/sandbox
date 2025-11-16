import uuid
import requests
from flask import render_template, request, redirect



def init_app(app, red, mode):
    app.add_url_rule('/sandbox/issue_agent_credential',  view_func=issue_agent_credential, methods=['GET', 'POST'], defaults={"mode": mode})
    return


def issue_agent_credential(mode):
    if request.method == "GET":
        # You can pre-fill defaults here if you want
        return render_template(
            "issuer_oidc/issue_agent_credential.html",
            issuer_api= mode.server + "sandbox/oidc4vc/issuer/api",
            callback_url=mode.server + "sandbox/issuer/callback",
        )

    # POST: read form data
  

    provider_id = request.form.get("provider_id", "").strip()
    provider_legalName = request.form.get("provider_legalName", "").strip()
    provider_brandName = request.form.get("provider_brandName", "").strip()
    provider_website = request.form.get("provider_website", "").strip()
    provider_jurisdiction = request.form.get("provider_jurisdiction", "").strip()
    provider_contacts = request.form.get("provider_contacts", "").strip()

    agent_description = request.form.get("agent_description", "").strip()
    model_name = request.form.get("model_name", "").strip()
    model_version = request.form.get("model_version", "").strip()
    model_publisher = request.form.get("model_publisher", "").strip()
    model_modality = request.form.get("model_modality", "").strip()
    model_model = request.form.get("model_model", "").strip()

    disclosure_raw = request.form.get("disclosure", "").strip()
    if disclosure_raw:
        disclosure = [item.strip() for item in disclosure_raw.split(",") if item.strip()]
    else:
        disclosure = ["all"]

    pre_authorized_code = "pre_authorized_code" in request.form

    # Build the agent_credential payload
    agent_credential = {
        "vct": vct,
        "name": cred_name,
        "description": cred_description,
        "provider": {
            "id": provider_id,
            "legalName": provider_legalName,
            "brandName": provider_brandName,
            "website": provider_website,
            "jurisdiction": provider_jurisdiction,
            "contacts": provider_contacts,
        },
        "agent": {
            "description": agent_description,
            "models": [
                {
                    "name": model_name,
                    "version": model_version,
                    "publisher": model_publisher,
                    "modality": model_modality,
                    "model": model_model,
                }
            ],
        },
        "disclosure": disclosure,
    }

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": api_key,
    }

    data = {
        "issuer_id": issuer_id,
        # vc must be an object with the credential type key
        "vc": {credential_type: agent_credential},
        "issuer_state": str(uuid.uuid1()),
        "credential_type": credential_type,
        "pre-authorized_code": pre_authorized_code,
        "callback": callback_url,
    }

    try:
        resp = requests.post(issuer_api, headers=headers, json=data, timeout=10)
    except Exception as e:
        return render_template(
            "issue_agent_credential.html",
            error=f"Request failed: {e}",
            issuer_api=issuer_api,
            issuer_id=issuer_id,
            api_key=api_key,
            callback_url=callback_url,
            credential_type=credential_type,
            vct=vct,
            cred_name=cred_name,
            provider_id=provider_id,
        )

    # Try to get redirect_uri (QR page)
    try:
        resp_json = resp.json()
    except ValueError:
        return render_template(
            "issue_agent_credential.html",
            error=f"Issuer did not return JSON. Body: {resp.text}",
            status_code=resp.status_code,
            issuer_api=issuer_api,
            issuer_id=issuer_id,
            api_key=api_key,
            callback_url=callback_url,
            credential_type=credential_type,
            vct=vct,
            cred_name=cred_name,
            provider_id=provider_id,
        )

    redirect_uri = resp_json.get("redirect_uri")
    if not redirect_uri:
        return render_template(
            "issue_agent_credential.html",
            error=f"No redirect_uri returned by issuer. Response: {resp_json}",
            status_code=resp.status_code,
            issuer_api=issuer_api,
            issuer_id=issuer_id,
            api_key=api_key,
            callback_url=callback_url,
            credential_type=credential_type,
            vct=vct,
            cred_name=cred_name,
            provider_id=provider_id,
        )

    # Success: redirect user to QR / wallet flow
    return redirect(redirect_uri)
