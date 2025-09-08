from __future__ import annotations

import json
from flask import request, render_template, current_app, jsonify
from datetime import datetime
import uuid
import vct_builder as vct

def init_app(app):
    app.add_url_rule('/attestation/generate', view_func=generate_attestation_page, methods=['GET'])
    app.add_url_rule('/attestation/api/generate', view_func=api_generate_attestation, methods=['POST'])

def generate_attestation_page():
    vct_uri = f"urn:uuid:{uuid.uuid4()}"
    with open("keys.json", "r") as f:
        keys = json.load(f)["ai_api"]
    if request.args.get("key") not in keys:
        return jsonify("Send an email to contact@talao.io to get an access"), 401
    return render_template('generate_attestation.html', vct=vct_uri,)

def _collect_simple_rendering(form) -> dict:
    bg = (form.get('bg_color') or '').strip()
    fg = (form.get('text_color') or '').strip()
    logo = (form.get('logo_uri') or '').strip()
    simple = {}
    if logo:
        simple['logo'] = {'uri': logo}
    if bg:
        simple['background_color'] = bg
    if fg:
        simple['text_color'] = fg
    return simple

def api_generate_attestation():
    vct_uri = (request.form.get('vct') or '').strip()
    if not vct_uri:
        return jsonify({"error": "vct is required"}), 400

    languages = request.form.getlist('languages')
    languages = [l.strip().lower() for l in languages if l and l.strip()]
    if not languages:
        languages = ['en']

    use_llm = bool(request.form.get('use_llm'))
    input_mode = (request.form.get('input_mode') or 'description').strip()

    cfg = vct.LLMConfig() if use_llm else None
    simple = _collect_simple_rendering(request.form)
    simple = simple if simple else None

    try:
        if input_mode == 'schema':
            file = request.files.get('schema_file')
            if not file or not file.filename:
                return jsonify({"error": "schema_file is required when input_mode=schema"}), 400
            raw = file.read().decode('utf-8', errors='replace')
            try:
                schema = json.loads(raw)
            except Exception as e:
                return jsonify({"error": f"Invalid JSON Schema file: {e}"}), 400

            payload = vct.generate_vc_type_metadata_from_schema(
                schema=schema,
                vct=vct_uri,
                cfg=cfg,
                use_llm=use_llm,
                require_llm=False,
                languages=languages,
                simple_rendering=simple,
            )
        else:
            description = (request.form.get('description') or '').strip()
            if not description:
                return jsonify({"error": "description is required when input_mode=description"}), 400

            payload = vct.generate_vc_type_metadata(
                description=description,
                vct=vct_uri,
                issuer=None,
                cfg=cfg,
                use_llm=use_llm,
                require_llm=False,
                languages=languages,
                simple_rendering=simple,
            )
    except Exception as e:
        return jsonify({"error": f"Failed to generate metadata: {e}"}), 500

    result = {**payload}

    return current_app.response_class(
        response=json.dumps(result, ensure_ascii=False, indent=2),
        status=200,
        mimetype="application/json; charset=utf-8",
    )
