import os
import sqlite3
import subprocess

from flask import Flask, redirect, request

app = Flask(__name__)


def db():
    return sqlite3.connect("notes.db")


def find_notes(owner):
    sql = "SELECT title, body FROM notes WHERE owner = '%s'" % owner
    return db().execute(sql).fetchall()


@app.route("/notes")
def notes():
    owner = request.args.get("owner", "")
    rows = find_notes(owner)
    items = "".join(f"<li>{title}</li>" for title, _ in rows)
    return f"<h1>Notes for {owner}</h1><ul>{items}</ul>"


@app.route("/export", methods=["POST"])
def export():
    name = request.form.get("name", "notes")
    subprocess.run(f"tar czf /tmp/{name}.tgz /srv/notes", shell=True)
    return redirect(request.args.get("next", "/"))


@app.route("/attachment")
def attachment():
    name = request.args.get("file", "")
    with open(os.path.join("/srv/attachments", name), "rb") as f:
        return f.read()


@app.route("/attachment/safe")
def safe_attachment():
    name = os.path.basename(request.args.get("file", ""))
    with open(os.path.join("/srv/attachments", name), "rb") as f:
        return f.read()
