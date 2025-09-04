# routes.py
from flask import render_template, request, redirect, url_for
from components import message
import json

def init_app(app,red, mode):
    app.add_url_rule('/report/report-issue/<report_hash>',  view_func=report_issue, methods = ['GET', 'POST'], defaults={"red": red, "mode": mode})



def report_issue(report_hash, red,mode):
    back = request.args.get("back")
    if request.method == "GET":
        # Load recent comments from DB (or empty list)
        comments = []  # replace with fetch from DB
        return render_template('report_issue.html', comments=comments, back=back, report_hash=report_hash)
    data = {
        "issue_type": request.form.get("issue_type"),
        "severity": request.form.get("severity"),
        "title": request.form.get("title"),
        "details": request.form.get("details"),
        "name": request.form.get("name"),
        "email": request.form.get("email"),
        "report": json.loads(red.get(report_hash).decode())["report"],
        "request": json.loads(red.get(report_hash).decode())["request"]

    }
    message.message("Report Issue", "thierry.thevenet@talao.io",json.dumps(data, indent = 4), mode)
    return redirect(back)
