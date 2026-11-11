import argparse
import base64
import hmac
from contextlib import closing
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit

DIRECTORY = Path(__file__).resolve().parent
TEMPLATES = DIRECTORY / "templates"
STATIC = DIRECTORY / "static"
COLLECTIONS = {"teams", "players", "staff", "gear", "lib", "tours", "results"}
MAX_BYTES = 20 * 1024 * 1024


def load_file(path: Path, default: str = "") -> str:
    """Helper reading text file if it exists."""
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return default


def render_app():
    """Load HTML templates, styles, and scripts dynamically from files."""
    pages_dir = TEMPLATES / "pages"
    pages = {}
    if pages_dir.exists():
        for file in sorted(pages_dir.glob("*.html")):
            pages[file.stem] = file.read_text(encoding="utf-8").removesuffix("\n")

    # Read CSS & JS from static/ or templates/ folder
    styles = load_file(STATIC / "styles.css") or load_file(TEMPLATES / "styles.css")
    scripts = load_file(STATIC / "scripts.js") or load_file(TEMPLATES / "scripts.js")

    # Escape "<" so template content cannot close the JSON script element.
    page_json = json.dumps(pages, ensure_ascii=False).replace("<", r"\u003c")
    values = {"styles": styles, "pages": page_json, "scripts": scripts}

    base = load_file(TEMPLATES / "base.html", "<html><body><div id='v'></div></body></html>")
    return re.sub(r"\{\{(styles|pages|scripts)\}\}", lambda m: values[m[1]], base).encode("utf-8")


def json_response(status, value):
    return status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8"


def read_state(database):
    try:
        with closing(sqlite3.connect(database)) as db:
            row = db.execute("SELECT revision, payload FROM app_state WHERE id = 1").fetchone()
    except sqlite3.Error:
        return json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Database read failed"})
    return json_response(HTTPStatus.OK, {"revision": row[0], "state": json.loads(row[1])}
                    if row else {"revision": 0, "state": None})


def write_state(database, content_type, content_length, stream):
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        return json_response(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "JSON required"})
    try:
        length = int(content_length)
        if not 0 < length <= MAX_BYTES:
            return json_response(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Invalid size"})
        body = json.loads(stream.read(length))
        revision, state = body["revision"], body["state"]
        if type(revision) is not int or revision < 0 or not isinstance(state, dict):
            raise ValueError
        for name in COLLECTIONS:
            entries = state[name]
            if not isinstance(entries, list) or any(
                not isinstance(entry, dict) or not isinstance(entry.get("id"), str)
                for entry in entries
            ):
                raise ValueError
            if len({entry["id"] for entry in entries}) != len(entries):
                raise ValueError
        payload = json.dumps(state, ensure_ascii=False, allow_nan=False)
    except (ValueError, KeyError, TypeError, RecursionError):
        return json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid state"})
    try:
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT revision FROM app_state WHERE id = 1").fetchone()
            current = row[0] if row else 0
            if revision != current:
                return json_response(HTTPStatus.CONFLICT, {"error": "Revision conflict"})
            db.execute(
                "INSERT INTO app_state VALUES (1, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, payload=excluded.payload",
                (revision + 1, payload),
            )
    except sqlite3.Error:
        return json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Database write failed"})
    return json_response(HTTPStatus.OK, {"revision": revision + 1})


def dispatch(database, method, path, content_type="", content_length="", stream=None):
    if method == "GET":
        if path in {"/", "/e_sports_team_manager.html"}:
            return HTTPStatus.OK, render_app(), "text/html; charset=utf-8"
        if path == "/api/state":
            return read_state(database)
    if method == "PUT" and path == "/api/state":
        return write_state(database, content_type, content_length, stream)
    return json_response(HTTPStatus.NOT_FOUND, {"error": "Not found"})


def initialize_database(database):
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS app_state ("
                   "id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL, payload TEXT NOT NULL)")


def create_application(username=None, password=None, database=DIRECTORY / "esports.db"):
    """Create a WSGI entry point (compatible with PythonAnywhere & local execution)."""
    initialize_database(database)
    authorization = None
    if username and password:
        authorization = b"Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8"))

    def application(environ, start_response):
        method = environ["REQUEST_METHOD"]
        head = method == "HEAD"
        headers = []
        if authorization and not hmac.compare_digest(environ.get("HTTP_AUTHORIZATION", "").encode("utf-8"), authorization):
            status, body, content_type = json_response(HTTPStatus.UNAUTHORIZED, {"error": "Sign in required"})
            headers.append(("WWW-Authenticate", 'Basic realm="Esports Manager", charset="UTF-8"'))
        elif authorization and method == "PUT" and environ.get("HTTP_ORIGIN") != "https://" + environ.get("HTTP_HOST", ""):
            status, body, content_type = json_response(HTTPStatus.FORBIDDEN, {"error": "Same-origin HTTPS required"})
        else:
            status, body, content_type = dispatch(
                database, "GET" if head else method, environ.get("PATH_INFO") or "/",
                environ.get("CONTENT_TYPE", ""), environ.get("CONTENT_LENGTH", ""), environ.get("wsgi.input"),
            )
        headers.extend([
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ])
        start_response(f"{status.value} {status.phrase}", headers)
        return [b"" if head else body]

    return application


# Global application object for PythonAnywhere WSGI container
application = create_application()


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        port = self.server.server_port
        return self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def do_GET(self):
        if not self.valid_host():
            return self.reply(*json_response(HTTPStatus.FORBIDDEN, {"error": "Local access only"}))
        self.reply(*dispatch(self.server.database, "GET", urlsplit(self.path).path))

    def do_PUT(self):
        origin = self.headers.get("Origin")
        if not self.valid_host() or (origin and origin != f"http://{self.headers.get('Host')}"):
            return self.reply(*json_response(HTTPStatus.FORBIDDEN, {"error": "Local access only"}))
        self.reply(*dispatch(
            self.server.database, "PUT", urlsplit(self.path).path,
            self.headers.get("Content-Type", ""), self.headers.get("Content-Length", ""), self.rfile,
        ))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", type=Path, default=DIRECTORY / "esports.db")
    args = parser.parse_args()
    if not (TEMPLATES / "base.html").is_file():
        parser.error("Keep templates/base.html next to app.py.")
    initialize_database(args.db)
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server:
        server.database = args.db.resolve()
        print(f"Open http://127.0.0.1:{server.server_port}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
