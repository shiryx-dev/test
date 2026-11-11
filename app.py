"""HTTP and SQLite backend for E-Sports Team Manager."""
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
COLLECTIONS = {"teams", "players", "staff", "gear", "lib", "tours", "results"}
MAX_BYTES = 20 * 1024 * 1024


def render_app():
    pages = {
        file.stem: file.read_text(encoding="utf-8").removesuffix("\n")
        for file in sorted((TEMPLATES / "pages").glob("*.html"))
    }
    # Escape "<" so template content cannot close the JSON script element.
    page_json = json.dumps(pages, ensure_ascii=False).replace("<", r"\u003c")
    values = {"styles": STYLES, "pages": page_json, "scripts": SCRIPTS}
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
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


def create_application(username, password, database=DIRECTORY / "esports.db"):
    """Create a password-protected WSGI entry point for HTTPS hosting."""
    if not username or ":" in username or len(password) < 16:
        raise ValueError("Set a username and a site password of at least 16 characters.")
    authorization = b"Basic " + base64.b64encode(f"{username}:{password}".encode("utf-8"))
    initialize_database(database)

    def application(environ, start_response):
        method = environ["REQUEST_METHOD"]
        head = method == "HEAD"
        headers = []
        if not hmac.compare_digest(environ.get("HTTP_AUTHORIZATION", "").encode("utf-8"), authorization):
            status, body, content_type = json_response(HTTPStatus.UNAUTHORIZED, {"error": "Sign in required"})
            headers.append(("WWW-Authenticate", 'Basic realm="Esports Manager", charset="UTF-8"'))
        elif method == "PUT" and environ.get("HTTP_ORIGIN") != "https://" + environ.get("HTTP_HOST", ""):
            status, body, content_type = json_response(HTTPStatus.FORBIDDEN, {"error": "Same-origin HTTPS required"})
        else:
            status, body, content_type = dispatch(
                database, "GET" if head else method, environ.get("PATH_INFO") or "/",
                environ.get("CONTENT_TYPE", ""), environ.get("CONTENT_LENGTH", ""), environ["wsgi.input"],
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


STYLES = r'''
:root{--bg:#eef1f7;--panel:#fff;--ink:#16213e;--mute:#5d6785;--line:#dde2ee;--side:#1b1f4b;--side-ink:#c9cdf2;--acc:#5b3df5;--acc-ink:#fff;--win:#0e9f6e;--loss:#e5484d;--draw:#b7791f;--soft:#f4f2ff;box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#10132b;--panel:#191d3d;--ink:#eceefb;--mute:#9aa3c7;--line:#2b3160;--side:#0b0d22;--side-ink:#aab0dc;--acc:#8b74ff;--acc-ink:#10132b;--win:#35c58f;--loss:#ff7b80;--draw:#e3b14f;--soft:#232857}}
:root[data-theme="dark"]{--bg:#10132b;--panel:#191d3d;--ink:#eceefb;--mute:#9aa3c7;--line:#2b3160;--side:#0b0d22;--side-ink:#aab0dc;--acc:#8b74ff;--acc-ink:#10132b;--win:#35c58f;--loss:#ff7b80;--draw:#e3b14f;--soft:#232857}
*{box-sizing:border-box}html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 Sarabun,"Noto Sans Thai",system-ui,sans-serif;display:flex;min-height:100vh}
h1,h2,h3,.brand{font-family:Kanit,"Noto Sans Thai",sans-serif;margin:0;font-weight:600}
aside{width:224px;background:var(--side);color:var(--side-ink);padding:22px 14px;position:sticky;top:0;height:100vh;flex-shrink:0;display:flex;flex-direction:column;gap:4px}
.brand{font-size:21px;color:#fff;padding:0 10px 0;line-height:1.2;cursor:pointer;user-select:none;transition:opacity .2s}.brand:hover{opacity:.85}.brand small{display:block;font:400 13px Sarabun,sans-serif;color:var(--side-ink);margin-top:2px}
aside button{all:unset;cursor:pointer;padding:10px 12px;border-radius:8px;font-weight:500;display:flex;justify-content:space-between;align-items:center}
aside button:hover{background:rgba(255,255,255,.08)}aside button.on{background:var(--acc);color:var(--acc-ink)}
aside button span{font-size:12px;opacity:.8}
aside .sp{flex:1}
main{flex:1;min-width:0;padding:28px clamp(16px,4vw,40px)}
header.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px}
h1{font-size:28px}
.bar{display:flex;gap:8px;flex-wrap:wrap}
input,select{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px 10px;width:100%}
.bar input{width:220px}
.btn{font:600 15px Sarabun,sans-serif;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;background:var(--acc);color:var(--acc-ink);display:inline-flex;align-items:center;justify-content:center;line-height:1.2;transition:all 0.15s ease}
.btn.g{background:transparent;color:var(--ink);border:1px solid var(--line)}.btn.g:hover{border-color:var(--mute)}
.btn.d{background:rgba(229,72,77,0.12);color:var(--loss);border:1px solid rgba(229,72,77,0.3);padding:6px 12px;font-size:13px}.btn.d:hover{background:var(--loss);color:#0a0a0b;border-color:var(--loss)}
.btn.s{padding:6px 12px;font-size:13px;background:rgba(242,183,5,0.12);color:var(--gold);border:1px solid rgba(242,183,5,0.3)}.btn.s:hover{background:var(--gold);color:#0a0a0b;border-color:var(--gold)}
:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
.wrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;min-width:560px}
th,td{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle}
th{font-weight:600;color:var(--mute);font-size:14px;background:var(--soft)}tr:last-child td{border-bottom:0}
td.act{text-align:right;white-space:nowrap}
td.act .act-wrap{display:inline-flex;align-items:center;justify-content:flex-end;gap:6px}
td.act .act-wrap .btn{min-width:58px;height:32px;padding:0 12px;font-size:13px;font-weight:600}
.tag{display:inline-block;padding:1px 10px;border-radius:99px;font-size:13px;font-weight:600;background:var(--soft);color:var(--acc)}
.tag.ok{color:var(--win);background:color-mix(in srgb,var(--win) 14%,transparent)}.tag.bad{color:var(--loss);background:color-mix(in srgb,var(--loss) 14%,transparent)}.tag.mid{color:var(--draw);background:color-mix(in srgb,var(--draw) 16%,transparent)}
.w{color:var(--win);font-weight:600}.l{color:var(--loss)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:22px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat b{font:600 30px Kanit,sans-serif;display:block;line-height:1.1}.stat span{color:var(--mute);font-size:14px}
.grid2{display:grid;grid-template-columns:3fr 2fr;gap:20px}
.grid2 h2{font-size:19px;margin-bottom:10px}
.empty{padding:34px 16px;text-align:center;color:var(--mute)}
dialog{border:1px solid var(--line);border-radius:14px;background:var(--panel);color:var(--ink);padding:22px;width:min(440px,92vw)}
dialog::backdrop{background:rgba(10,12,35,.55)}
dialog h2{font-size:20px;margin-bottom:14px}
label{display:block;font-size:14px;color:var(--mute);margin-top:10px;margin-bottom:3px}
.foot{display:flex;justify-content:flex-end;gap:8px;margin-top:20px}
@media(max-width:820px){
 body{flex-direction:column}
 aside{width:100%;height:auto;position:sticky;top:0;z-index:5;flex-direction:row;overflow-x:auto;padding:calc(8px + env(safe-area-inset-top,0px)) 10px 8px;gap:4px;margin-top:calc(-1 * env(safe-area-inset-top,0px))}
 .brand,aside .sp,aside button span{display:none}aside button{white-space:nowrap}
 .grid2{grid-template-columns:1fr}.bar input{width:100%}
}
@media (prefers-reduced-motion:no-preference){main>section{animation:in .2s ease-out}@keyframes in{from{opacity:.4}}}

:root,:root:not([data-theme="light"]),:root[data-theme="dark"],:root[data-theme="light"]{color-scheme:dark;--bg:#0a0a0b;--panel:#101012;--ink:#f3f3f1;--mute:#9a9a9f;--line:#2a2a2e;--side:#0a0a0b;--side-ink:#e8e8e6;--acc:#f2b705;--acc-ink:#0a0a0b;--win:#3ddc97;--loss:#ff5a5f;--draw:#f2b705;--soft:#17171a;--red:#e03a3e;--gold:#f2b705}
body{flex-direction:column;font-family:Inter,Sarabun,"Noto Sans Thai",system-ui,sans-serif}
h1,h2,h3,.brand{font-family:"Barlow Condensed",Kanit,sans-serif;font-weight:700}
aside{width:100%;height:64px;flex-direction:row;align-items:center;gap:4px;padding:0 clamp(12px,3vw,32px);margin-top:0;overflow-x:auto;background:#0a0a0b;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.brand{display:flex;align-items:center;gap:10px;padding:0 20px 0 0;font-size:21px;letter-spacing:.04em;line-height:1;text-transform:uppercase;white-space:nowrap;color:#fff}
.brand small{display:inline;margin:0;font:inherit;color:var(--gold)}
aside button{height:100%;padding:0 14px;border-radius:0;font:600 14px Inter,Sarabun,sans-serif;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap;color:var(--side-ink)}
aside button:hover{background:none;color:var(--gold)}
aside button.on{background:none;color:#fff;box-shadow:inset 0 -3px 0 var(--red)}
aside button span{display:none}
aside button.cta{height:auto;padding:9px 20px;border-radius:8px;background:#fff;color:#0a0a0b;letter-spacing:.04em}
aside button.cta:hover{background:var(--gold);color:#0a0a0b}
main{width:100%;max-width:1320px;margin:0 auto}
main h1{font-size:40px;line-height:1;text-transform:uppercase;color:var(--gold)}
.btn{background:#fff;color:#0a0a0b;border-radius:6px}.btn:hover{background:var(--gold)}
.btn.g{background:transparent;color:var(--ink)}.btn.s{background:transparent;color:var(--gold)}.btn.d{background:transparent;color:var(--loss)}
input,select{background:#0a0a0b;border-radius:6px}
.wrap,dialog{border-radius:6px}
.stat,.hcard{border:1px solid #2e2b20;border-radius:6px;background:linear-gradient(135deg,#1f1c10 0,#0f0f11 45%)}
th{background:#141416;font-size:13px;letter-spacing:.06em;text-transform:uppercase}
tr:hover td{background:#141416}
.tag{border-radius:4px}
.stat b{font-family:"Barlow Condensed",Kanit,sans-serif;font-size:36px}
.tls{display:flex;margin-bottom:34px}
.tl{flex:1;position:relative;padding:12px 8px 26px;text-align:center;border-left:1px solid var(--line);background:#0f0f11;min-width:0}
.tl:first-child{border-left:0}
.tl small{display:block;font-size:12px;font-weight:600;color:var(--mute);letter-spacing:.06em}
.tl b{display:block;font-size:16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tl::before{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:#3a3a3e}
.tl.done::before,.tl.now::before{background:var(--red)}
.tl.now{background:linear-gradient(#3b1114,#170a0b)}.tl.now small{color:var(--red)}
.tl i{position:absolute;left:50%;bottom:-14px;transform:translateX(-50%);width:28px;height:28px;border-radius:50%;display:grid;place-items:center;font-style:normal;font-weight:700;font-size:15px;background:#0a0a0b;border:3px solid #3a3a3e;color:#0a0a0b;z-index:1}
.tl.done i{background:#fff;border-color:#fff}.tl.now i{background:var(--red);border-color:#ffffff40}
.hero{display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap;margin-bottom:8px}
.hero h1{font-size:clamp(36px,6vw,60px);max-width:14ch;line-height:.95}
.ptag{display:inline-block;margin-top:12px;padding:0 9px;background:var(--gold);color:#0a0a0b;font:700 16px "Barlow Condensed",sans-serif;letter-spacing:.06em;text-transform:uppercase}
.hcard{padding:18px 24px;min-width:250px}.hcard b{display:block;font:700 26px "Barlow Condensed",Kanit,sans-serif}.hcard span{color:var(--mute);font-size:14px}
.more{display:flex;align-items:flex-end;margin:34px 0 26px;color:var(--gold);font-weight:600;letter-spacing:.06em;text-transform:uppercase;font-size:15px}
.more::before,.more::after{content:"";flex:1;height:1px;background:var(--line);margin-bottom:0}
.more span{padding:14px 48px;clip-path:polygon(7% 0,93% 0,100% 100%,0 100%);background:#141416}
.grid2 h2{font-size:26px;text-transform:uppercase}
.rk{display:flex;align-items:center;gap:16px;padding:14px 18px;border-bottom:1px solid var(--line)}.rk:last-child{border:0}
.rk em{font:700 30px "Barlow Condensed",sans-serif;font-style:normal;width:28px;text-align:center}
.rk .lg{width:42px;height:42px;border-radius:50%;display:grid;place-items:center;background:#1b1b1f;border:1px solid var(--line);color:var(--gold);font:700 15px "Barlow Condensed",sans-serif;overflow:hidden;flex-shrink:0}
.rk .lg img{width:100%;height:100%;object-fit:contain;padding:4px}
.rk:first-child .lg{background:var(--gold);color:#0a0a0b;border-color:var(--gold)}
.rk b{flex:1;font-size:18px}.rk u{text-decoration:none;font-weight:700}
@media(max-width:820px){aside{height:56px;margin:0;padding:0 12px}.brand{display:flex;font-size:18px}.hero h1{font-size:40px}.tl b{font-size:13px}.more span{padding:12px 24px}}
.mode{padding:8px 14px;border-radius:6px;margin-bottom:18px;font-size:14px;font-weight:600;border:1px solid var(--line)}
.mode.admin{color:var(--gold);background:#1f1c10;border-color:#4a4220}.mode.user{color:var(--mute);background:#141416}
.role{padding:2px 10px;border-radius:4px;font:700 13px Inter,sans-serif;letter-spacing:.08em;margin:0 8px;background:var(--gold);color:#0a0a0b;white-space:nowrap}
.login{max-width:820px;margin:40px auto}.lg2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:18px}
.lc{padding:22px;border:1px solid #2e2b20;border-radius:6px;background:linear-gradient(135deg,#1f1c10 0,#0f0f11 45%)}
.lc h2{font-size:26px;text-transform:uppercase}.lc p{color:var(--mute);min-height:48px}#le{color:var(--loss);font-size:14px;min-height:22px}.lc .btn{margin-top:8px}
@media(max-width:700px){.lg2{grid-template-columns:1fr}}
.dgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:14px;margin-bottom:26px}
.dc{position:relative;display:block;aspect-ratio:3/4;border:1px solid #3a3a42;border-radius:8px;overflow:hidden;color:var(--ink);text-decoration:none;background:linear-gradient(#b3322f 0,#7a2224 44%,#23232b 45%,#1c1c23 100%);cursor:pointer;transition:transform .15s, border-color .15s}
.dc:hover{border-color:var(--gold);transform:translateY(-2px)}
.dp{position:absolute;top:10px;right:12px;color:var(--gold);font:700 20px "Barlow Condensed",sans-serif;z-index:1}
.di{position:absolute;left:0;right:0;top:0;height:46%;display:grid;place-items:end center}
.di svg{width:64%;height:92%}
.gl{font:700 70px "Barlow Condensed",sans-serif;color:#ffffff38;line-height:1;margin-bottom:10px}
.dn{position:absolute;left:12px;right:12px;bottom:12px}.dn b{display:block;font-size:18px}.dn small{color:var(--mute);font-size:13px}
a.dc:hover{border-color:var(--gold)}
.dp{position:absolute;top:10px;right:12px;color:var(--gold);font:700 20px "Barlow Condensed",sans-serif;z-index:1}
.dt{position:absolute;top:34px;right:12px;color:var(--gold);font-size:11px;font-weight:600;z-index:1}
.di{position:absolute;left:0;right:0;top:0;height:46%;display:grid;place-items:end center}
.di svg{width:64%;height:92%}
.gl{font:700 70px "Barlow Condensed",sans-serif;color:#ffffff38;line-height:1;margin-bottom:10px}
.dn{position:absolute;left:12px;right:12px;bottom:12px}.dn b{display:block;font-size:18px}.dn small{color:var(--mute);font-size:13px}
.pbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px}
a.btn{text-decoration:none;display:inline-block}
.btn.clr{background:transparent;color:var(--loss);border:1px solid var(--loss)}.btn.clr:hover{background:var(--loss);color:#0a0a0b}
.rem{color:var(--gold);font-weight:700}
.prof{display:grid;grid-template-columns:200px 1fr;gap:24px;align-items:start}
.prof .dc{width:200px}.prof h1{font-size:clamp(40px,6vw,64px)}.sub{color:var(--mute);margin:6px 0 18px}
.sec{font-size:28px;margin:28px 0 12px}
.pk{display:flex;align-items:center;gap:10px}.bar2{flex:1;height:6px;min-width:80px;background:#26262b;border-radius:3px}.bar2 i{display:block;height:100%;background:var(--gold);border-radius:3px}
.num{color:var(--gold);font-weight:600}
a.pl{color:inherit;text-decoration:none}a.pl:hover{color:var(--gold)}
@media(max-width:700px){.prof{grid-template-columns:1fr}.prof .dc{width:170px}}
input[type=checkbox]{width:auto;accent-color:var(--gold);transform:scale(1.25)}input[type=file]{padding:6px}
.pv{display:block;max-width:100%;max-height:180px;margin:10px 0;border-radius:6px;border:1px solid var(--line)}.pv[hidden]{display:none}
.ggrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px;margin-bottom:24px}
.gc{position:relative;border:1px solid #3a3a42;border-radius:8px;overflow:hidden;background:#17171c}.gc.ed{cursor:pointer}.gc.ed:hover{border-color:var(--gold)}
.gi{aspect-ratio:4/3;display:grid;place-items:center;background:linear-gradient(#7a2224,#23232b 85%);font-size:52px;overflow:hidden}.gi img{width:100%;height:100%;object-fit:cover}
.gb{padding:10px 12px}.gb b{display:block;font-size:16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.gb small{color:var(--mute)}
.gm{display:flex;justify-content:space-between;align-items:center;gap:6px;margin-top:8px}
.gx{all:unset;cursor:pointer;position:absolute;top:8px;left:8px;width:28px;height:28px;border-radius:50%;background:#0a0a0bcc;color:#fff;display:grid;place-items:center;font-size:13px;border:1px solid #ffffff55;z-index:2}.gx:hover{background:var(--loss);color:#0a0a0b}.gx:focus-visible{outline:3px solid var(--acc)}
.bd{border:1px solid var(--loss)}.bd:disabled{opacity:.4;cursor:default}
.fb{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.fb select{width:auto;min-width:200px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}.fb .chips{margin:0}
.chip{all:unset;cursor:pointer;padding:7px 18px;border:1px solid var(--line);border-radius:6px;font-size:14px;font-weight:600;color:var(--mute);background:#141416;display:inline-flex;align-items:center;gap:6px;transition:all .15s ease}
.chip:hover{color:#fff;border-color:var(--gold);background:#1a1a20}
.chip.on{background:var(--gold);color:#0a0a0b;border-color:var(--gold);font-weight:700}
.chip:focus-visible{outline:3px solid var(--acc)}
.tc .chip i{width:10px;height:10px;border-radius:50%;background:var(--c)}.tc .chip.on{background:color-mix(in srgb,var(--c) 30%,#0a0a0b);color:#fff;border-color:var(--c)}
.tg{margin-bottom:28px}.tg-hdr{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.tg-hdr a.t-link{display:inline-flex;align-items:center;gap:12px;color:#ffffff;text-decoration:none;transition:color 0.2s ease}
.tg-hdr a.t-link:hover{color:var(--gold)}
.tg-hdr a.t-link:hover h2{color:var(--gold)}
.t-logo{width:38px;height:38px;border-radius:6px;background:#141416;border:1px solid var(--line);padding:3px;object-fit:contain;flex-shrink:0;display:inline-grid;place-items:center;font-weight:700;font-size:12px;color:var(--gold);transition:border-color .2s}
.tg-hdr a.t-link:hover .t-logo{border-color:var(--gold)}
.t-logo.sm{width:26px;height:26px;padding:2px;border-radius:4px}
.tg h2{font-size:26px;margin:0;color:#ffffff;transition:color 0.2s ease}.tg h2 small{font:500 14px Sarabun,sans-serif;color:var(--mute);margin-left:10px}
.stf{display:flex;flex-wrap:wrap;gap:4px 18px;color:var(--mute);font-size:14px;margin:4px 0 12px}.stf b{color:var(--ink)}
.ty{display:inline-block;background:color-mix(in srgb,var(--c) 22%,transparent);color:var(--c);border-radius:4px;padding:1px 9px;font-size:13px;font-weight:700}
.gc{border-top:4px solid var(--c,#3a3a42)}.gi{background:linear-gradient(color-mix(in srgb,var(--c,#7a2224) 60%,#0a0a0b),#1a1a20 92%)}

html{-webkit-text-size-adjust:100%;background:#0a0a0b}
body{min-height:100vh;min-height:100dvh}
button,a,select,.chip,.dc,.gc{touch-action:manipulation;-webkit-tap-highlight-color:transparent}
aside{scrollbar-width:none;scroll-snap-type:x proximity;overscroll-behavior-x:contain}aside::-webkit-scrollbar{display:none}
aside button{scroll-snap-align:center}
.wrap{-webkit-overflow-scrolling:touch}
.tg{content-visibility:auto;contain-intrinsic-size:auto 420px}
.rk b{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.form{display:flex;gap:3px;align-items:center}.form i{width:9px;height:9px;border-radius:50%}
.fW{background:var(--win)}.fD{background:var(--draw)}.fL{background:var(--loss)}
.cg{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:16px;margin-bottom:12px}
.cc{border:1px solid #2e2b20;border-radius:6px;background:linear-gradient(135deg,#1f1c10 0,#0f0f11 45%);padding:16px 18px}
.cc h3{font-size:22px;text-transform:uppercase;margin-bottom:10px}
.hb{display:flex;align-items:center;gap:10px;padding:5px 0}
.hl{width:96px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:14px}
.ht{flex:1;height:10px;background:#26262b;border-radius:5px;overflow:hidden;min-width:0}.ht i{display:block;height:100%;background:var(--gold)}
.ht.st{display:flex}.st .sw{background:var(--win)}.st .sd{background:var(--draw)}.st .sl{background:var(--loss)}
.hb>b{min-width:52px;text-align:right;font-size:14px;white-space:nowrap}
.lgd{display:flex;gap:12px;flex-wrap:wrap;color:var(--mute);font-size:13px;margin:10px 0 0}.lgd i{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
.nodata{color:var(--mute);padding:8px 0}

.vsel{display:flex;gap:8px;align-items:center;margin-bottom:18px}.vsel select{flex:1;min-width:0}.vsel .btn{flex-shrink:0}
.vh{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;text-align:center;margin-bottom:14px}
.vh h2{font-size:clamp(22px,4.5vw,34px);text-transform:uppercase;line-height:1.05}.vh small{color:var(--mute)}
.vl{width:64px;height:64px;border-radius:50%;display:grid;place-items:center;margin:0 auto 8px;background:#1b1b1f;border:1px solid var(--line);color:var(--gold);font:700 20px "Barlow Condensed",sans-serif;overflow:hidden;padding:6px}
.vl img{width:100%;height:100%;object-fit:contain}
.vs{font:700 22px "Barlow Condensed",sans-serif;color:var(--red)}
.vt{border:1px solid var(--line);border-radius:6px;background:var(--panel);overflow:hidden}
.vr{display:grid;grid-template-columns:1fr minmax(100px,1.3fr) 1fr;align-items:center;text-align:center;padding:11px 10px;border-bottom:1px solid var(--line)}.vr:last-child{border:0}
.vr span{color:var(--mute);font-size:13px;letter-spacing:.03em}.vr>b{font:700 22px "Barlow Condensed",Inter,sans-serif}.vr>b.vw{color:var(--gold)}
.vr .form{justify-content:center}
.vp{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
.vp>div{border:1px solid var(--line);border-radius:6px;background:var(--panel);padding:12px 14px;font-size:14px;color:var(--mute)}.vp b{display:block;color:var(--ink);font-size:15px}

.bk{display:flex;gap:34px;overflow-x:auto;padding:4px 2px 14px;scroll-snap-type:x mandatory;margin-bottom:10px;-webkit-overflow-scrolling:touch}
.bc{flex:0 0 min(260px,78vw);scroll-snap-align:start;display:flex;flex-direction:column;gap:14px}
.bh{text-align:center;padding:8px;background:#141416;border-bottom:3px solid var(--red)}.bh small{display:block;color:var(--mute);font-size:12px;letter-spacing:.06em;text-transform:uppercase}
.bm{flex:1;display:flex;flex-direction:column;justify-content:space-around;gap:14px}
.mc{position:relative;border:1px solid var(--line);border-radius:6px;background:var(--panel)}
.bc:not(:last-child) .mc::after{content:"";position:absolute;left:100%;top:50%;width:34px;height:1px;background:#3a3a3e}
.mt{display:flex;justify-content:space-between;gap:10px;padding:10px 12px;border-left:3px solid transparent}.mt+.mt{border-top:1px solid var(--line)}
.mt span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.mt b{font:700 20px "Barlow Condensed",sans-serif}
.mt.win{border-left-color:var(--gold);background:#1f1c10}.mt.win b{color:var(--gold)}.mt.out{color:var(--mute)}
.dr{display:block;text-align:center;color:var(--draw);font-size:12px;padding:2px 0 6px;font-weight:600}
.binfo{display:flex;gap:6px 18px;flex-wrap:wrap;color:var(--mute);font-size:14px;margin:2px 0 16px}.binfo b{color:var(--ink)}
@media(max-width:820px){
 .btn,select,input:not([type=checkbox]){min-height:44px}.btn.s,.btn.d{min-height:40px}.chip{padding:9px 16px;min-height:40px}
 aside button{padding:0 16px}
 .bar{width:100%}.bar .btn{flex:1}
 .stats{grid-template-columns:repeat(2,1fr)}.stats .stat:last-child:nth-child(odd){grid-column:1/-1}
 .dgrid{grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:10px}
 .fb select{width:100%}
 .hl{width:82px}
 dialog{width:100%;max-width:100%;margin:auto 0 0;border-radius:16px 16px 0 0;max-height:92dvh;overflow:auto;padding-bottom:calc(22px + env(safe-area-inset-bottom,0px))}
 .foot{position:sticky;bottom:0;background:var(--panel);padding-top:10px}
 .vl{width:44px;height:44px;font-size:16px}
 .rk{gap:10px;padding:12px}.rk .lg{width:36px;height:36px}
 main{padding-bottom:calc(28px + env(safe-area-inset-bottom,0px))}
}
@media(prefers-reduced-motion:no-preference){
 dialog[open]{animation:sheet .22s ease-out}@keyframes sheet{from{transform:translateY(20px);opacity:0}}
 .ht i{transform-origin:left;animation:grow .5s ease-out}@keyframes grow{from{transform:scaleX(0)}}
 .mc,.cc,.vt{animation:fadein .25s ease-out}@keyframes fadein{from{opacity:0;transform:translateY(6px)}}
}
.site-footer{text-align:center;color:var(--mute);font-size:13px;margin-top:32px}
'''

SCRIPTS = r'''
const pages = JSON.parse(document.getElementById("page-templates").textContent);
function page(name, values = {}) {
  return pages[name].replace(/\{\{(\w+)\}\}/g, (_, key) => values[key]);
}
document.getElementById("f").addEventListener("submit", event => event.preventDefault());

const KEY="esm-v4";
const E={
 teams:{t:"ทีม",add:"เพิ่มทีม",cols:[["name","ชื่อทีม","text"],["game","เกมที่แข่ง","text"],["region","ประเทศ/ภูมิภาค","text"],["coach","โค้ช","text"]]},
 players:{t:"นักแข่ง",add:"เพิ่มนักแข่ง",cols:[["name","ชื่อในเกม (IGN)","text"],["real","ชื่อจริง","text"],["team","ทีม","ref:teams"],["role","บทบาท","text"],["price","ค่าตัว (USD)","num"],["agents","ตัวละครที่เล่น","ag"]]},
 staff:{t:"โค้ชและสตาฟฟ์",add:"เพิ่มบุคลากร",cols:[["name","ชื่อเล่น / ชื่อ","text"],["real","ชื่อจริง","text"],["team","ทีม","ref:teams"],["role","ตำแหน่ง","sel:หัวหน้าโค้ช|โค้ช|ผู้ช่วยโค้ช|โค้ชสมรรถภาพ|ผู้จัดการทีม|นักวิเคราะห์|สตาฟฟ์"]]},
 gear:{t:"อุปกรณ์",add:"เพิ่มอุปกรณ์",cols:[["name","ชื่ออุปกรณ์","text"],["brand","ยี่ห้อ / รุ่น","text"],["type","ประเภท","sel:เมาส์|คีย์บอร์ด|หูฟัง|จอภาพ|เก้าอี้|คอมพิวเตอร์|เมาส์แพด|อื่น ๆ"],["owner","ผู้ใช้งาน","ref:players"],["status","สถานะ","sel:พร้อมใช้|ส่งซ่อม|สูญหาย"],["cost","ราคา (บาท)","num"],["bought","วันที่ซื้อ","date","h"],["serial","หมายเลขซีเรียล","text","h"],["note","หมายเหตุ","text","h"],["img","รูปอุปกรณ์ (ว่างได้ ระบบดึงรูปจากรุ่นเดียวกันให้)","img","h"]]},
 lib:{t:"คลังอุปกรณ์",add:"เพิ่มรุ่นอุปกรณ์",cols:[["name","ชื่อรุ่น","text"],["brand","ยี่ห้อ","text"],["type","ประเภท","sel:เมาส์|คีย์บอร์ด|หูฟัง|จอภาพ|เก้าอี้|คอมพิวเตอร์|เมาส์แพด|อื่น ๆ"],["img","รูปภาพประจำรุ่น (อุปกรณ์รุ่นเดียวกันทุกชิ้นจะใช้รูปนี้)","img","h"]]},
 tours:{t:"รายการแข่ง",add:"เพิ่มรายการแข่ง",cols:[["name","ชื่อรายการ","text"],["game","เกม","text"],["start","วันเริ่มแข่ง","date"],["place","สถานที่","text"],["prize","เงินรางวัล (บาท)","num"]]},
 results:{t:"ผลการแข่ง",add:"บันทึกผล",cols:[["tour","รายการแข่ง","ref:tours"],["date","วันที่แข่ง","date"],["a","ทีม A","ref:teams"],["b","ทีม B","ref:teams"],["sa","คะแนน A","num"],["sb","คะแนน B","num"]]}
};

const LOGOS={
 "Paper Rex":"https://owcdn.net/img/627f00bf7eddf.png",
 "Sentinels":"https://owcdn.net/img/62a26fb66601f.png",
 "Fnatic":"https://owcdn.net/img/632b72bdc55db.png",
 "Gen.G Esports":"https://owcdn.net/img/6034177b213b2.png",
 "EDward Gaming":"https://owcdn.net/img/62fe055b86860.png",
 "FULL SENSE":"https://owcdn.net/img/60f78d387dd47.png",
 "Team Secret":"https://owcdn.net/img/6132dd99395f1.png",
 "Rex Regum Qeon":"https://owcdn.net/img/627f00bf7eddf.png",
 "DRX":"https://owcdn.net/img/620023405b63b.png",
 "KIWOOM DRX":"https://owcdn.net/img/620023405b63b.png",
 "T1":"https://owcdn.net/img/602d334e3e3b3.png",
 "ZETA DIVISION":"https://owcdn.net/img/61b369c0d9225.png",
 "100 Thieves":"https://owcdn.net/img/5f85faeb2cb98.png",
 "Cloud9":"https://owcdn.net/img/5f85fb0bc7a9f.png",
 "NRG":"https://owcdn.net/img/6007e547bbd31.png",
 "G2 Esports":"https://owcdn.net/img/62a220dc55f30.png",
 "LOUD":"https://owcdn.net/img/62002167d41ef.png",
 "Team Heretics":"https://owcdn.net/img/6322cb2b48eef.png",
 "Karmine Corp":"https://owcdn.net/img/6274e7978d331.png",
 "Team Liquid":"https://owcdn.net/img/5f85fa3dc9ddb.png",
 "Natus Vincere":"https://owcdn.net/img/61b1be048b9f0.png",
 "Bilibili Gaming":"https://owcdn.net/img/62fe084f981e4.png"
};
const getLogo=name=>LOGOS[name]||"";
const tLogoHtml=(name,cls="t-logo")=>{
 const src=getLogo(name);
 return src?`<img class="${cls}" src="${src}" alt="${esc(name)}" onerror="this.style.display='none'">`:`<span class="${cls}">${esc(name.slice(0,2).toUpperCase())}</span>`;
};

const uid=()=>Date.now().toString(36)+Math.random().toString(36).slice(2,6);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function seed(){
 const T=["Bangkok Titans","Siam Phoenix","Chiang Mai Wolves"].map((n,i)=>({id:"t"+i,name:n,game:"Valorant",region:"ไทย",coach:["โค้ชบอส","โค้ชนิว","โค้ชเฟิร์ส"][i]}));
 const P=[["Nova","สมชาย ใจดี","t0","Duelist",215,"Jett 28 18 520 390; Raze 16 9 290 240; Neon 8 4 130 120; Yoru 4 2 60 70"],["Rex","ธนกร แสงทอง","t0","IGL",190,"Omen 24 15 330 310; Astra 14 8 190 180; Viper 10 6 130 120"],["Mint","ปวีณา รักเกม","t1","Controller",192,"Viper 22 13 300 270; Clove 15 8 210 200; Brimstone 9 5 120 115"],["Zen","กิตติ มั่นคง","t1","Sentinel",180,"Cypher 20 12 260 230; Killjoy 17 9 240 210; Chamber 9 5 160 130"],["Fang","ภูมิ พิทักษ์","t2","Initiator",210,"Sova 26 17 380 330; Fade 14 8 210 190; Skye 8 5 110 100; Breach 6 3 80 85"],["Ally","ณัฐ วงศ์ไทย","t2","Duelist",213,"Reyna 22 14 450 340; Jett 18 10 340 290; Phoenix 6 3 100 95"]].map((p,i)=>({id:"p"+i,name:p[0],real:p[1],team:p[2],role:p[3],price:p[4],agents:pa(p[5])}));
 const G=[["Logitech G Pro X Superlight","เมาส์","p0","พร้อมใช้"],["Wooting 60HE","คีย์บอร์ด","p1","พร้อมใช้"],["HyperX Cloud III","หูฟัง","p2","ส่งซ่อม"],["ZOWIE XL2566K 360Hz","จอภาพ","","พร้อมใช้"]].map((g,i)=>({id:"g"+i,name:g[0],type:g[1],owner:g[2],status:g[3]}));
 const R=[{id:"r0",name:"SEA Valorant Open 2026",game:"Valorant",start:"2026-09-12",place:"สิงคโปร์",prize:500000},{id:"r1",name:"SEA Qualifier to World Tour 2027",game:"Valorant",start:"2026-12-05",place:"ออนไลน์",prize:200000}];
 const M=[["r0","2026-09-12","t0","t1",2,1],["r0","2026-09-13","t1","t2",2,2],["r0","2026-09-14","t0","t2",0,2]].map((m,i)=>({id:"m"+i,tour:m[0],date:m[1],a:m[2],b:m[3],sa:m[4],sb:m[5]}));
 const GG=[...G,...realGear()];return{teams:[...T,...realTeams()],players:[...P,...realPlayers()],gear:GG,tours:R,results:M,staff:realStaff(),lib:libFrom(GG)};
}

const connected=location.protocol==="http:"||location.protocol==="https:";
let S, revision=0, saving=false;
if(!connected){try{S=JSON.parse(localStorage.getItem(KEY))}catch(e){}}
if(!S||!S.teams)S=seed();
S.staff=S.staff||[];S.lib=S.lib||[];
async function save(previous){
 saving=true;
 try{
  if(!connected){localStorage.setItem(KEY,JSON.stringify(S));return ""}
  const response=await fetch("/api/state",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({revision,state:S})});
  if(response.status===409){S=previous;return "ข้อมูลถูกแก้ไขจากอีกหน้าต่าง กรุณาโหลดหน้าใหม่ก่อนบันทึกอีกครั้ง"}
  if(!response.ok)throw Error(response.status);
  revision=(await response.json()).revision;
  return "";
 }catch(e){
  S=previous;
  return connected?"บันทึกไม่สำเร็จ กรุณาตรวจว่าเซิร์ฟเวอร์ Python ยังทำงานอยู่ แล้วโหลดหน้าใหม่เพื่อตรวจสอบข้อมูล":"บันทึกไม่สำเร็จ กรุณาตรวจสอบพื้นที่จัดเก็บของเบราว์เซอร์";
 }finally{saving=false}
}
const nm=(k,id)=>{const r=S[k].find(x=>x.id===id);return r?r.name:"—"};
const fd=d=>d?new Date(d+"T00:00:00").toLocaleDateString("th-TH",{day:"numeric",month:"short",year:"numeric"}):"—";
let role=null;try{role=sessionStorage.getItem("esm-role")}catch(e){}
const XT=["bracket","compare"];
let tab=(location.hash||"#home").slice(1),q="";
let pid="";if(tab.startsWith("player-")){pid=tab.slice(7);tab="player"}
if(!(tab==="home"||tab==="player"||E[tab]||XT.includes(tab)))tab="home";
const tabs=[["home","ภาพรวม"],...Object.keys(E).map(k=>[k,E[k].t]),["bracket","ผลตามรายการ"],["compare","เปรียบเทียบทีม"]];

function nav(){
 document.getElementById("nav").innerHTML='<div class="brand" onclick="goHome()"><svg width="30" height="30" viewBox="0 0 30 30" aria-hidden="true"><path d="M2 3l9 12-9 12h6l9-12L8 3zM28 3l-9 12 9 12h-6l-9-12 9-12z" fill="#f2b705"/></svg>E-Sports <small>Team Manager</small></div>'+
 tabs.map(([k,l])=>`<button data-t="${k}" class="${k===tab||(tab==="player"&&k==="players")?"on":""}">${l}${E[k]?`<span>${S[k].length}</span>`:""}</button>`).join("")+'<div class="sp"></div><span class="role">'+(role==="admin"?"ADMIN":"USER")+'</span>'+(role==="admin"?'<button class="cta" data-record="1">บันทึกผล</button>':'')+'<button id="lo">ออกจากระบบ</button>';
 const on=document.querySelector("#nav button.on");if(on)on.scrollIntoView({inline:"center",block:"nearest"});
}

function goHome(){
 tab="home";
 q="";
 location.hash="home";
 render();
 scrollTo(0,0);
}

function standings(rs=S.results){
 const m={};S.teams.forEach(t=>m[t.id]={id:t.id,f:[],n:t.name,p:0,w:0,d:0,l:0,pt:0,df:0});
 [...rs].sort((x,y)=>String(x.date).localeCompare(String(y.date))).forEach(r=>{const a=m[r.a],b=m[r.b];if(!a||!b)return;a.p++;b.p++;a.df+=r.sa-r.sb;b.df+=r.sb-r.sa;
  if(r.sa>r.sb){a.w++;b.l++;a.pt+=3;a.f.push("W");b.f.push("L")}else if(r.sa<r.sb){b.w++;a.l++;b.pt+=3;a.f.push("L");b.f.push("W")}else{a.d++;b.d++;a.pt++;b.pt++;a.f.push("D");b.f.push("D")}});
 return Object.values(m).sort((x,y)=>y.pt-x.pt||y.df-x.df);
}

function cell(c,r){const[k,,ty]=c,v=r[k];
 if(ty==="ag")return esc((v||[]).map(x=>x.n).join(", "))||"—";
 if(ty.startsWith("ref"))return esc(nm(ty.split(":")[1],v));
 if(ty==="date")return fd(v);
 if(ty==="num")return (k==="prize"||k==="cost")?Number(v||0).toLocaleString("th-TH"):k==="price"?(v?"$"+esc(v):"—"):esc(v);
 if(k==="status")return`<span class="tag ${v==="พร้อมใช้"?"ok":v==="ส่งซ่อม"?"mid":"bad"}">${esc(v)}</span>`;
 if(k==="type"&&TC[v])return`<span class="ty" style="--c:${TC[v]}">${esc(v)}</span>`;
 if(k==="name"||k==="type"||k==="role"){
   if(k==="name"){
     if(tab==="players")return`<a class="pl" href="#player-${r.id}"><b>${esc(v)}</b></a>`;
     if(tab==="teams")return`<div style="display:flex;align-items:center;gap:10px">${tLogoHtml(r.name)}<b>${esc(v)}</b></div>`;
     return`<b>${esc(v)}</b>`;
   }
   return esc(v);
 }
 return esc(v)||"—";
}

function resRow(r){
 const nameA=nm("teams",r.a), nameB=nm("teams",r.b);
 return`<tr><td><div style="display:flex;align-items:center;gap:8px">${tLogoHtml(nameA,"t-logo sm")}${esc(nameA)}</div></td><td class="${r.sa>r.sb?"w":r.sa<r.sb?"l":""}"><b>${r.sa} : ${r.sb}</b></td><td><div style="display:flex;align-items:center;gap:8px">${tLogoHtml(nameB,"t-logo sm")}${esc(nameB)}</div></td><td>${esc(nm("tours",r.tour))}</td></tr>`
}

function hero(){
 const now=new Date();
 const today=[now.getFullYear(),String(now.getMonth()+1).padStart(2,"0"),String(now.getDate()).padStart(2,"0")].join("-");
 const T=[...S.tours].sort((a,b)=>a.start.localeCompare(b.start));
 if(!T.length)return'<header class="top"><h1>Overview</h1></header>';
 const cur=T.find(t=>t.start&&t.start>=today)||[...T].reverse().find(t=>t.start)||T[0];
 const mon=d=>d?new Date(d+"T00:00:00").toLocaleDateString("en-US",{month:"short"}).toUpperCase():"";
 const tl=T.map(t=>{const s=t.start&&t.start<today?"done":t===cur&&t.start?"now":"next";return`<div class="tl ${s}"><small>${t.start===today?"วันนี้":mon(t.start)||"ยังไม่กำหนดวัน"}</small><b>${esc(t.name)}</b><i>${s==="done"?"✓":""}</i></div>`}).join("");
 const top=standings().find(t=>t.p>0);
 return`<div class="tls">${tl}</div><div class="hero"><div><h1>${esc(cur.name)}</h1>${cur.place?`<span class="ptag">${esc(cur.place)}</span>`:""}</div><div class="hcard"><b>${top?esc(top.n):"—"}</b><span>คะแนนรวมสูงสุด</span></div></div>`;
}

const ROLE={Jett:"Duelist",Raze:"Duelist",Reyna:"Duelist",Phoenix:"Duelist",Neon:"Duelist",Yoru:"Duelist",Iso:"Duelist",Sage:"Sentinel",Cypher:"Sentinel",Killjoy:"Sentinel",Chamber:"Sentinel",Deadlock:"Sentinel",Omen:"Controller",Brimstone:"Controller",Viper:"Controller",Astra:"Controller",Harbor:"Controller",Clove:"Controller",Sova:"Initiator",Breach:"Initiator",Skye:"Initiator","KAY/O":"Initiator",Fade:"Initiator",Gekko:"Initiator"};
function pa(s){return String(s||"").split(";").map(x=>x.trim().split(/\s+/)).filter(a=>a[0]&&a.length>=5).map(a=>({n:a[0],g:+a[1]||0,w:+a[2]||0,k:+a[3]||0,d:+a[4]||0}))}
function agStr(a){return(a||[]).map(x=>[x.n,x.g,x.w,x.k,x.d].join(" ")).join("; ")}
const SIL='<svg viewBox="0 0 100 110" aria-hidden="true"><circle cx="50" cy="34" r="20" fill="#0a0a0b"/><path d="M8 110c0-30 18-48 42-48s42 18 42 48z" fill="#0a0a0b"/></svg>';
const abbr=t=>t?t.name.split(" ").map(w=>w[0]).join("").slice(0,3).toUpperCase():"—";
function pcard(p,link=true){const t=S.teams.find(x=>x.id===p.team);const b=`<span class="dp">${p.price?"$"+Number(p.price):"—"}</span><span class="dt">${esc(abbr(t))}</span><div class="di">${SIL}</div><div class="dn"><b>${esc(p.name)}</b><small>${esc(t?t.name:"ไม่มีทีม")}</small></div>`;return link?`<a class="dc" href="#player-${p.id}">${b}</a>`:`<div class="dc">${b}</div>`}

function playerPage(){
 const p=S.players.find(x=>x.id===pid);
 if(!p)return page("player-missing");
 const t=S.teams.find(x=>x.id===p.team),A=[...(p.agents||[])].sort((a,b)=>b.g-a.g);
 const sum=k=>A.reduce((s,a)=>s+a[k],0),tg=sum("g"),tw=sum("w"),tk=sum("k"),td=sum("d");
 const pct=(a,b)=>b?Math.round(a/b*1000)/10:0,kd=(k,d)=>d?(k/d).toFixed(2):"—";
 const cards=A.slice(0,5).map(a=>`<div class="dc"><span class="dp">${pct(a.g,tg)}%</span><span class="dt">${esc(ROLE[a.n]||"Agent")}</span><div class="di"><span class="gl">${esc(a.n[0])}</span></div><div class="dn"><b>${esc(a.n)}</b><small>${a.g} เกม, ชนะ ${pct(a.w,a.g)}%</small></div></div>`).join("");
 const rows=A.map(a=>{const w=pct(a.w,a.g);return`<tr><td><b>${esc(a.n)}</b></td><td>${esc(ROLE[a.n]||"—")}</td><td>${a.g}</td><td class="${w>=50?"w":"l"}">${w}%</td><td class="num">${kd(a.k,a.d)}</td><td><div class="pk"><div class="bar2"><i style="width:${pct(a.g,tg)}%"></i></div><span class="num">${pct(a.g,tg)}%</span></div></td></tr>`}).join("");
 const sts=[[A.length?esc(A[0].n):"—","ตัวละครหลัก"],[tg,"เกมที่เล่น"],[pct(tw,tg)+"%","อัตราชนะ"],[kd(tk,td),"K/D"]];
 return page("player", {
  price: p.price?"$"+Number(p.price):"—",
  card: pcard(p,false),
  name: esc(p.name),
  realName: esc(p.real||""),
  role: esc(p.role||""),
  team: esc(t?t.name:"ไม่มีทีม"),
  stats: sts.map(s=>`<div class="stat"><b>${s[0]}</b><span>${s[1]}</span></div>`).join(""),
  pickRates: tg?'<div class="cc"><h2 class="sec">สัดส่วนการเลือกตัวละคร</h2>'+A.map(a=>`<div class="hb"><span class="hl">${esc(a.n)}</span><div class="ht" aria-hidden="true"><i style="width:${pct(a.g,tg)}%;background:var(--gold)"></i></div><b>${pct(a.g,tg)}%</b></div>`).join("")+'</div>':"",
  agentDetails: A.length?`<div class="dgrid">${cards}</div><h2 class="sec">สถิติตัวละครทั้งหมด</h2><div class="wrap"><table><tr><th>ตัวละคร</th><th>บทบาท</th><th>เกม</th><th>ชนะ</th><th>K/D</th><th>อัตราการเลือก</th></tr>${rows}</table></div>`:`<div class="wrap"><div class="empty">ยังไม่มีสถิติตัวละคร${role==="admin"?" เพิ่มได้ที่หน้านักแข่ง > แก้ไข":""}</div></div>`
 });
}

const IMG={};
const GI={"เมาส์":"🖱️","คีย์บอร์ด":"⌨️","หูฟัง":"🎧","จอภาพ":"🖥️","เก้าอี้":"🪑","คอมพิวเตอร์":"💻"};

async function delMany(ids){
 if(role!=="admin"||saving||!ids.length)return;
 const linked=S.results.filter(r=>tab==="teams"?(ids.includes(r.a)||ids.includes(r.b)):tab==="tours"&&ids.includes(r.tour)).length;
  const impact=linked?" ผลการแข่งขันที่เกี่ยวข้อง "+linked+" รายการจะถูกลบด้วย":"";
  if(!confirm("ลบ "+ids.length+" รายการใช่ไหม?"+impact))return;
  const previous=structuredClone(S);
 S[tab]=S[tab].filter(x=>!ids.includes(x.id));
 if(tab==="teams"){[...S.players,...S.staff].forEach(p=>{if(ids.includes(p.team))p.team=""});S.results=S.results.filter(r=>!ids.includes(r.a)&&!ids.includes(r.b))}
 if(tab==="players")S.gear.forEach(g=>{if(ids.includes(g.owner))g.owner=""});
 if(tab==="tours")S.results=S.results.filter(r=>!ids.includes(r.tour));
 const error=await save(previous);
  if(error){alert(error);return}
  render();
}

function VTl(){return[
["Paper Rex","Pacific","สิงคโปร์ (SEA)","alecks"],["Rex Regum Qeon","Pacific","อินโดนีเซีย (SEA)","Jovi"],["Team Secret","Pacific","ฟิลิปปินส์ (SEA)","Spin"],["FULL SENSE","Pacific","ไทย (SEA)","THEELOVEFAMILY"],
["Global Esports","Pacific","อินเดีย","FrosT"],["Gen.G Esports","Pacific","เกาหลีใต้"],["Nongshim RedForce","Pacific","เกาหลีใต้"],["T1","Pacific","เกาหลีใต้"],["KIWOOM DRX","Pacific","เกาหลีใต้"],["DetonatioN FocusMe","Pacific","ญี่ปุ่น"],["ZETA DIVISION","Pacific","ญี่ปุ่น"],["VARREL","Pacific","ญี่ปุ่น"],
...["100 Thieves","Cloud9","Evil Geniuses","FURIA","KRÜ Esports","Leviatán","LOUD","MIBR","NRG","Sentinels","G2 Esports","ENVY"].map(n=>[n,"Americas",""]),
...["BBL Esports","Fnatic","FUT Esports","Karmine Corp","Natus Vincere","Team Heretics","Team Liquid","Team Vitality","GIANTX","Gentle Mates","ULF Esports","PCIFIC Esports"].map(n=>[n,"EMEA",""]),
...["All Gamers","Bilibili Gaming","EDward Gaming","FunPlus Phoenix","JD Gaming","Nova Esports","Titan Esports Club","Trace Esports","TYLOO","Wolves Esports","XLG Esports","Dragon Ranger Gaming"].map(n=>[n,"China",""])]}

function realTeams(){return VTl().map((t,i)=>({id:"v"+i,name:t[0],game:"Valorant",region:"VCT "+t[1]+(t[2]?" / "+t[2]:""),coach:t[3]||""}))}
function realPlayers(){const ids={};VTl().forEach((t,i)=>ids[t[0]]="v"+i);
 const R=[["Paper Rex",[["invy","Adrian Jiggs Reyes"],["Jinggg","Wang Jing Jie"],["f0rsakeN","Jason Susanto"],["d4v41","Khalish Rusyaidee"],["something","Ilya Petrov"]]],
 ["Rex Regum Qeon",[["Monyet","Cahya Nugraha"],["xffero","David Monangin"],["Jemkin","Maksim Batorov"],["Kushy","Bryan Carlos Setiawan"],["crazyguy","Ngô Công Anh"],["Xan","Xan Ng"]]],
 ["Team Secret",[["kellyS","Kelly Sedillo"],["natz","Jonathan Adiputra"],["STYRON","Tidus Goh"],["Zeus","Jhian Vega"],["Sylvan","Go Young-sup"]]],
 ["FULL SENSE",[["Killua","Tanate Teerasawad"],["primmie","Papaphat Sriprapha"],["JitBoyS","Jittana Nokngam"],["seph1roth","Chinnakrit Phoojaroen"],["thyy","Anupong Preamsak"]]],
 ["Global Esports",[["PatMen","Patrick Mendoza"],["Kr1stal","Savva Fedorov"],["xavi8k","Xavier Juan"],["Autumn","Kale Dunne"],["Deryeon","Derrick Yee"]]],
 ["Gen.G Esports",[["Xiesta","Jung Si-hwan"],["Karon","Kim Won-tae"],["t3xture","Kim Na-ra"],["Raxcal","Kim Min-seok"],["Dambi","Lee Hyuk-kyu"],["MaKo","Kim Myeong-gwan"]]],
 ["Nongshim RedForce",[["WoohyuN","Moon Woo-hyun"],["Xross","Jeonghwan"],["UdoTan","Go Kyung-won"],["Rb","Goo Sang-min"],["Francis","Kim Mu-bin"],["Ivy","Park Sung-hyeon"]]],
 ["DetonatioN FocusMe",[["Meiy","Ibuki Seki"],["SSeeS","Tomonori Okimura"],["yatsuka","Kazuya Ikeda"],["Caedye","Amon Mateus Okakura"],["Akame","Yu Gwang-hui"]]],
 ["T1",[["stax","Kim Gu-taek"],["BuZz","Yu Byeong-cheol"],["iZu","Ham Woo-ju"]]],
 ["KIWOOM DRX",[["Flicker","Kim Tae-hee"]]],
 ["ZETA DIVISION",[["SugarZ3ro","Shota Watanabe"]]]];
 const out=[];R.forEach(([tm,ps])=>ps.forEach(([n,r])=>out.push({id:"vp"+out.length,name:n,real:r,team:ids[tm],role:"",price:0,agents:[]})));return out}

let pl="all",pt="",gt="all";
const TC={"เมาส์":"#e5484d","คีย์บอร์ด":"#4f8dff","หูฟัง":"#a77bff","จอภาพ":"#22c593","เก้าอี้":"#ff9a3c","คอมพิวเตอร์":"#3cc8f0","เมาส์แพด":"#ff6fb1","อื่น ๆ":"#9a9aa2"};
function norm(s){return String(s||"").toLowerCase().replace(/[^a-z0-9\u0e00-\u0e7f+]/g,"")}
function gimg(g){const f=a=>(a.find(x=>x.img&&norm(x.name)===norm(g.name))||{}).img;return g.img||f(S.gear)||f(S.lib)||""}
function ensureLib(o){if(!o.name)return;const l=S.lib.find(x=>norm(x.name)===norm(o.name));if(!l)S.lib.push({id:uid(),name:o.name,brand:o.brand||"",type:o.type||"",img:o.img||""});else if(!l.img&&o.img)l.img=o.img}
function libFrom(g){const m={};g.forEach(x=>{const k=norm(x.name);if(!m[k])m[k]={id:"l"+Object.keys(m).length,name:x.name,brand:x.brand||"",type:x.type,img:""}});return Object.values(m)}
const tm=id=>{const t=S.teams.find(x=>x.id===id);if(!t)return pl==="all"&&!pt;return(pl==="all"||(pl==="SEA"?/\(SEA\)/.test(t.region):t.region.includes("VCT "+pl)))&&(!pt||pt===id)};

function fbar(k){
 const L=["all","SEA","Pacific","Americas","EMEA","China"];
 const teams=S.teams.filter(t=>pl==="all"||(pl==="SEA"?/\(SEA\)/.test(t.region):t.region.includes("VCT "+pl)));
 let h=`<div class="fb"><div class="chips">${L.map(x=>`<button class="chip ${pl===x?"on":""}" data-pl="${x}">${x==="all"?"ทุกลีก":x}</button>`).join("")}</div>`;
 if(k!=="teams")h+=`<select id="pt" aria-label="เลือกทีม"><option value="">ทุกทีม</option>${teams.map(t=>`<option value="${t.id}" ${t.id===pt?"selected":""}>${esc(t.name)}</option>`).join("")}</select>`;
 h+=`</div>`;
 if(k==="gear")h+=`<div class="chips tc"><button class="chip ${gt==="all"?"on":""}" data-gt="all">ทุกประเภท</button>${Object.keys(TC).map(x=>`<button class="chip ${gt===x?"on":""}" data-gt="${x}" style="--c:${TC[x]}"><i></i>${x}</button>`).join("")}</div>`;
 return h}

function grouped(rows){
 if(!rows.length)return"";
 const g={};rows.forEach(p=>(g[p.team||""]=g[p.team||""]||[]).push(p));
 const ids=S.teams.map(t=>t.id).filter(i=>g[i]);if(g[""])ids.push("");
 return ids.map(i=>{const t=S.teams.find(x=>x.id===i),st=S.staff.filter(s=>s.team===i);
  return`<section class="tg">
   <div class="tg-hdr">
     <a href="${t?`#compare`: '#'}" onclick="${t?`ca='${t.id}';tab='compare';location.hash='compare';render();return false;`:''}" class="t-link">
       ${t?tLogoHtml(t.name):''}
       <h2>${esc(t?t.name:"ไม่มีทีม")}<small>${t?esc(t.region)+" / ":""}${g[i].length} คน</small></h2>
     </a>
   </div>
   ${st.length?`<p class="stf">${st.map(s=>`<span><b>${esc(s.name)}</b> ${esc(s.role)}</span>`).join("")}</p>`:""}
   <div class="dgrid">${g[i].map(p=>pcard(p)).join("")}</div>
  </section>`}).join("")}

function gcard(g){const o=S.players.find(x=>x.id===g.owner),adm=role==="admin",c=TC[g.type]||"#9a9aa2",im=gimg(g);
 return`<div class="gc ${adm?"ed":""}" style="--c:${c}" ${adm?`data-e="${g.id}"`:""}>${adm?`<button class="gx" data-x="${g.id}" aria-label="ลบ ${esc(g.name)}">✕</button>`:""}<div class="gi">${im?`<img loading="lazy" decoding="async" src="${im}" alt="${esc(g.name)}">`:`<span>${GI[g.type]||"🎮"}</span>`}</div><div class="gb"><b>${esc(g.name)}</b><small>${esc(g.brand||"")}</small><div class="gm"><span class="ty">${esc(g.type)}</span><span class="tag ${g.status==="พร้อมใช้"?"ok":g.status==="ส่งซ่อม"?"mid":"bad"}">${esc(g.status)}</span></div><small>${o?esc(o.name):"ไม่มีผู้ใช้"}</small></div></div>`}

function lcard(l){const c=TC[l.type]||"#9a9aa2",n=S.gear.filter(g=>norm(g.name)===norm(l.name)).length,adm=role==="admin";
 return`<div class="gc ${adm?"ed":""}" style="--c:${c}" ${adm?`data-e="${l.id}"`:""}>${adm?`<button class="gx" data-x="${l.id}" aria-label="ลบ ${esc(l.name)}">✕</button>`:""}<div class="gi">${l.img?`<img loading="lazy" decoding="async" src="${l.img}" alt="${esc(l.name)}">`:`<span>${GI[l.type]||"🎮"}</span>`}</div><div class="gb"><b>${esc(l.name)}</b><small>${esc(l.brand||"")}</small><div class="gm"><span class="ty">${esc(l.type)}</span><small>ใช้โดย ${n} คน</small></div></div></div>`}

function realStaff(){const ids={};VTl().forEach((t,i)=>ids[t[0]]="v"+i);
 const R=[["Paper Rex",[["alecks","Alexandre Sallé","หัวหน้าโค้ช"],["Wendler","Ashton Wendler","ผู้ช่วยโค้ช"],["Panda","Laijhun Cheng","โค้ชสมรรถภาพ"],["Tommy","Kumaresan Ramani","ผู้จัดการทีม"]]],
 ["Rex Regum Qeon",[["Jovi","Jovanni Vera","หัวหน้าโค้ช"],["Warbirds","Evan Olzem","ผู้ช่วยโค้ช"],["Rebecca","Rebecca Wong","โค้ชสมรรถภาพ"],["dave","David Hunter","นักวิเคราะห์"],["Jomengz","Jonathan Hoo","สตาฟฟ์"],["SeasoNz","Joe Lai","ผู้จัดการทีม"]]],
 ["Team Secret",[["Spin","Peter Bradford","หัวหน้าโค้ช"]]],
 ["FULL SENSE",[["THEELOVEFAMILY","Thanaphat Limpaphan","หัวหน้าโค้ช"],["Sushiboys","Panyawat Subsiriroj","ผู้ช่วยโค้ช"],["Crws","Thanamethk Mahatthananuyut","โค้ช"]]],
 ["Global Esports",[["FrosT","Hector Rosario","หัวหน้าโค้ช"],["balax","Thong Chern Kwi","โค้ช"],["vladk0r","Vladimir Kornev","ผู้ช่วยโค้ช"],["Platoon","Daniel Zhou","นักวิเคราะห์"],["Vatsal","Vatsal Uniyal","ผู้จัดการทีม"],["taeri","Hose Son","สตาฟฟ์"],["UnknowN","Minseong Kim","สตาฟฟ์"]]]];
 const out=[];R.forEach(([tm2,ps])=>ps.forEach(([n,r,ro])=>out.push({id:"vs"+out.length,name:n,real:r,team:ids[tm2],role:ro})));return out}

function realGear(){const P=realPlayers(),pid=n=>(P.find(p=>p.name===n)||{}).id||"";
 const Z=["ZOWIE XL2566K","BenQ ZOWIE","จอภาพ"],W=["Wooting 60HE","Wooting","คีย์บอร์ด"],S2=["Logitech G Pro X Superlight 2","Logitech G","เมาส์"],H=["HyperX Cloud III","HyperX","หูฟัง"],A=["Artisan Ninja FX Zero Soft","Artisan","เมาส์แพด"];
 const L=[["f0rsakeN",[Z,["Logitech G Pro X Superlight","Logitech G","เมาส์"],W,H,A],"prosettings.net / Sportskeeda ปี 2024"],
 ["d4v41",[Z,S2,W,["Razer Hammerhead Pro V2","Razer","หูฟัง"],["SteelSeries Dex","SteelSeries","เมาส์แพด"]],"prosettings.net / Sportskeeda ปี 2024"],
 ["something",[["ZOWIE XL2566X+","BenQ ZOWIE","จอภาพ"],S2,["Yuki Aim 65% Keyboard","Yuki Aim","คีย์บอร์ด"],H,["SteelSeries QcK Heavy","SteelSeries","เมาส์แพด"]],"Sportskeeda ปี 2024 / ZOWIE ปี 2025"],
 ["Jinggg",[["ZOWIE XL2546K","BenQ ZOWIE","จอภาพ"],["FinalMouse Starlight-12","FinalMouse","เมาส์"],["Logitech G Pro X Headset","Logitech G","หูฟัง"],A],"ข้อมูลปี 2022 อาจเปลี่ยนแล้ว"]];
 const out=[];L.forEach(([n,gs,src])=>gs.forEach(g=>out.push({id:"vg"+out.length,name:g[0],brand:g[1],type:g[2],owner:pid(n),status:"พร้อมใช้",cost:0,bought:"",serial:"",note:"แหล่งข้อมูล: "+src,img:""})));return out}

function rankList(st){return st.map((t,i)=>`<div class="rk"><em>${i+1}</em><span class="lg">${tLogoHtml(t.n,"t-logo")}</span><b>${esc(t.n)}</b><span class="form" aria-label="ฟอร์ม 5 แมตช์ล่าสุด">${t.f.slice(-5).map(x=>`<i class="f${x}"></i>`).join("")}</span><u>${t.pt} pts</u></div>`).join("")}

function home(){
 const st=standings().filter(t=>t.p>0),rec=[...S.results].sort((a,b)=>b.date.localeCompare(a.date)).slice(0,5);
 const stats=[["ทีม",S.teams.length],["นักแข่ง",S.players.length],["อุปกรณ์ที่พร้อมใช้",S.gear.filter(g=>g.status==="พร้อมใช้").length+"/"+S.gear.length],["รายการแข่ง",S.tours.length],["แมตช์ที่แข่งแล้ว",S.results.length]];
 return page("home", {
  hero: hero(),
  stats: stats.map(s=>`<div class="stat"><b>${s[1]}</b><span>${s[0]}</span></div>`).join(""),
  standings: st.length?rankList(st):'<div class="empty">ยังไม่มีผลการแข่งสำหรับจัดอันดับ</div>',
  recentResults: rec.length?`<table><tr><th>ทีม A</th><th>สกอร์</th><th>ทีม B</th><th>รายการ</th></tr>${rec.map(resRow).join("")}</table>`:'<div class="empty">ยังไม่มีผลการแข่ง</div>',
  charts: charts(st)
 });
}

function list(k){
 const e=E[k];let rows=S[k];
 if(q){const s=q.toLowerCase();rows=rows.filter(r=>e.cols.some(c=>{const v=c[2].startsWith("ref")?nm(c[2].split(":")[1],r[c[0]]):r[c[0]];return String(v??"").toLowerCase().includes(s)}))}
 if(k==="teams")rows=rows.filter(t=>pl==="all"||(pl==="SEA"?/\(SEA\)/.test(t.region):t.region.includes("VCT "+pl)));
 if(k==="players"||k==="staff")rows=rows.filter(r=>tm(r.team));if(k==="gear")rows=rows.filter(r=>{const o=S.players.find(p=>p.id===r.owner);return((pl==="all"&&!pt)||(o&&tm(o.team)))&&(gt==="all"||r.type===gt)});
 if(k==="results")rows=[...rows].sort((a,b)=>b.date.localeCompare(a.date));
 const ex=k==="results"?"<th>ผู้ชนะ</th>":"";
 const body=rows.map(r=>`<tr>${role==="admin"?`<td><input type="checkbox" class="rc" data-id="${r.id}" aria-label="เลือก"></td>`:""}${e.cols.filter(c=>!c[3]).map(c=>`<td>${cell(c,r)}</td>`).join("")}${k==="results"?`<td>${r.sa===r.sb?'<span class="tag mid">เสมอ</span>':`<span class="tag ok">${esc(nm("teams",r.sa>r.sb?r.a:r.b))}</span>`}</td>`:""}${role==="admin"?`<td class="act"><div class="act-wrap"><button class="btn s" data-e="${r.id}">แก้ไข</button><button class="btn d" data-x="${r.id}">ลบ</button></div></td>`:""}</tr>`).join("");
 return page(k, {
  query: esc(q),
  actions: role==="admin"?`<button class="btn d bd" id="bd" disabled>ลบที่เลือก</button><button class="btn" data-a="1">${e.add}</button>`:"",
  filters: ["teams","players","staff","gear"].includes(k)?fbar(k):"",
  groups: k==="players"?grouped(rows):"",
  cards: (k==="lib"&&rows.length?`<div class="ggrid">${rows.map(lcard).join("")}</div>`:"") || (k==="gear"&&rows.length?`<div class="ggrid">${rows.map(gcard).join("")}</div>`:""),
  table: rows.length?`<table><tr>${role==="admin"?'<th><input type="checkbox" id="ca" aria-label="เลือกทั้งหมด"></th>':""}${e.cols.filter(c=>!c[3]).map(c=>`<th>${c[1]}</th>`).join("")}${ex}${role==="admin"?"<th style=\"text-align:right\">การจัดการ</th>":""}</tr>${body}</table>`:`<div class="empty">${q?"ไม่พบรายการที่ค้นหา ลองใช้คำอื่น":`ยังไม่มี${e.t} กด “${e.add}” เพื่อเริ่มต้น`}</div>`
 });
}

let ca="",cb="",bt="";
const hb=rows=>{const mx=Math.max(1,...rows.map(r=>r.v));return rows.map(r=>`<div class="hb"><span class="hl" title="${esc(r.l)}">${esc(r.l)}</span><div class="ht"><i style="width:${Math.max(3,r.v/mx*100)}%;${r.c?"background:"+r.c:""}"></i></div><b>${r.t!==undefined?r.t:r.v}</b></div>`).join("")};

function charts(st){
 const act=st.filter(t=>t.p>0).slice(0,8);
 const wl=act.map(t=>`<div class="hb"><span class="hl" title="${esc(t.n)}">${esc(t.n)}</span><div class="ht st" role="img" aria-label="ชนะ ${t.w} เสมอ ${t.d} แพ้ ${t.l}">${t.w?`<i class="sw" style="flex:${t.w}"></i>`:""}${t.d?`<i class="sd" style="flex:${t.d}"></i>`:""}${t.l?`<i class="sl" style="flex:${t.l}"></i>`:""}</div><b>${t.w}-${t.d}-${t.l}</b></div>`).join("");
 const AG={};S.players.forEach(p=>(p.agents||[]).forEach(a=>AG[a.n]=(AG[a.n]||0)+a.g));
 const ags=Object.entries(AG).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([n,v])=>({l:n,v,t:v+" เกม"}));
 const GT={};S.gear.forEach(g=>GT[g.type]=(GT[g.type]||0)+1);
 const gts=Object.entries(GT).sort((a,b)=>b[1]-a[1]).map(([n,v])=>({l:n,v,c:TC[n]||"#9a9aa2"}));
 const cnt=s=>S.gear.filter(g=>g.status===s).length;
 const no=m=>`<p class="nodata">${m}</p>`;
 return`<div class="more"><span>สถิติและกราฟ</span></div><div class="cg">
 <div class="cc"><h3>ผลงานทีม</h3>${act.length?wl+`<p class="lgd"><span><i style="background:var(--win)"></i>ชนะ</span><span><i style="background:var(--draw)"></i>เสมอ</span><span><i style="background:var(--loss)"></i>แพ้</span></p>`:no("ยังไม่มีผลการแข่ง")}</div>
 <div class="cc"><h3>ตัวละครยอดนิยม</h3>${ags.length?hb(ags):no("ยังไม่มีสถิติตัวละคร")}</div>
 <div class="cc"><h3>อุปกรณ์ตามประเภท</h3>${gts.length?hb(gts)+`<p class="lgd"><span><i style="background:var(--win)"></i>พร้อมใช้ ${cnt("พร้อมใช้")}</span><span><i style="background:var(--draw)"></i>ส่งซ่อม ${cnt("ส่งซ่อม")}</span><span><i style="background:var(--loss)"></i>สูญหาย ${cnt("สูญหาย")}</span></p>`:no("ยังไม่มีอุปกรณ์")}</div></div>`;
}

function tstat(id){
 const s=standings().find(x=>x.id===id)||{p:0,w:0,d:0,l:0,pt:0,df:0,f:[]};
 const ps=S.players.filter(p=>p.team===id),oid=ps.map(p=>p.id),gr=S.gear.filter(g=>oid.includes(g.owner));
 let k=0,d=0;ps.forEach(p=>(p.agents||[]).forEach(a=>{k+=a.k;d+=a.d}));
 const val=ps.reduce((a,p)=>a+Number(p.price||0),0);
 return{...s,wr:s.p?Math.round(s.w/s.p*100):0,n:ps.length,val,avg:ps.length?Math.round(val/ps.length):0,kd:(k||d)?(d?k/d:k):null,gr:gr.filter(g=>g.status==="พร้อมใช้").length,gt:gr.length,ps}
}

function compare(){
 const T=S.teams,st=standings(),layout = content => page("compare", {
  content: content
 });
 if(T.length<2)return layout('<div class="wrap"><div class="empty">ต้องมีอย่างน้อย 2 ทีมจึงจะเปรียบเทียบได้</div></div>');
 if(!T.find(t=>t.id===ca)||!T.find(t=>t.id===cb)||ca===cb){const act=st.filter(t=>t.p>0),base=act.length>=2?act:st;ca=base[0].id;cb=base[1].id}
 const A=tstat(ca),B=tstat(cb),ta=T.find(t=>t.id===ca),tb=T.find(t=>t.id===cb);
 const opt=v=>T.map(t=>`<option value="${t.id}" ${t.id===v?"selected":""}>${esc(t.name)}</option>`).join("");
 const usd=v=>"$"+Number(v).toLocaleString("en-US");
 const M=[["แข่งแล้ว","p",0],["ชนะ","w",1],["เสมอ","d",0],["แพ้","l",-1],["คะแนน","pt",1],["ผลต่างสกอร์","df",1],["อัตราชนะ","wr",1,v=>v+"%"],["จำนวนนักแข่ง","n",0],["ค่าตัวรวม","val",0,usd],["ค่าตัวเฉลี่ย","avg",0,usd],["K/D (จากสถิติตัวละคร)","kd",1,v=>v===null?"—":v.toFixed(2)],["อุปกรณ์พร้อมใช้","gr",1,(v,s)=>v+"/"+s.gt]];
 const rows=M.map(([l,k,dir,f])=>{const x=A[k],y=B[k],fm=f||(v=>v);let xa="",xb="";if(dir&&x!==null&&y!==null&&x!==y){const aw=dir>0?x>y:x<y;xa=aw?"vw":"";xb=aw?"":"vw"}return`<div class="vr"><b class="${xa}">${fm(x,A)}</b><span>${l}</span><b class="${xb}">${fm(y,B)}</b></div>`}).join("");
 const fm5=s=>`<span class="form">${s.f.slice(-5).map(x=>`<i class="f${x}"></i>`).join("")||"—"}</span>`;
 const hd=(t,i)=>`<div><span class="vl">${tLogoHtml(t.name)}</span><h2>${esc(t.name)}</h2><small>${esc(t.region||"")}</small></div>`;
 const m=S.results.filter(r=>(r.a===ca&&r.b===cb)||(r.a===cb&&r.b===ca)).sort((x,y)=>y.date.localeCompare(x.date));
 let wa=0,wb=0,dr=0;m.forEach(r=>{const x=r.a===ca?r.sa:r.sb,y=r.a===ca?r.sb:r.sa;if(x>y)wa++;else if(x<y)wb++;else dr++});
 const ros=s=>s.ps.length?s.ps.map(p=>esc(p.name)).join(", "):"ยังไม่มีนักแข่ง";
 return layout(page("compare-data", {
  firstOptions: opt(ca),
  secondOptions: opt(cb),
  firstTeam: hd(ta),
  secondTeam: hd(tb),
  metrics: rows,
  firstForm: fm5(A),
  secondForm: fm5(B),
  firstRoster: ros(A),
  secondRoster: ros(B),
  headToHead: m.length?`<div class="stats"><div class="stat"><b>${wa}</b><span>${esc(ta.name)} ชนะ</span></div><div class="stat"><b>${dr}</b><span>เสมอ</span></div><div class="stat"><b>${wb}</b><span>${esc(tb.name)} ชนะ</span></div></div><div class="wrap"><table><tr><th>ทีม A</th><th>สกอร์</th><th>ทีม B</th><th>รายการ</th></tr>${m.map(resRow).join("")}</table></div>`:'<div class="wrap"><div class="empty">สองทีมนี้ยังไม่เคยเจอกันในระบบ</div></div>'
 }));
}

function bracket(){
 const T=[...S.tours].sort((a,b)=>a.start.localeCompare(b.start));
 const layout = content => page("bracket", {
  recordButton: role==="admin"?'<div class="bar"><button class="btn" data-record="1">บันทึกผล</button></div>':"",
  content: content
 });
 if(!T.length)return layout('<div class="wrap"><div class="empty">ยังไม่มีรายการแข่ง</div></div>');
 if(!T.find(t=>t.id===bt))bt=(T.find(t=>S.results.some(r=>r.tour===t.id))||T[0]).id;
 const tr=T.find(t=>t.id===bt),ms=S.results.filter(r=>r.tour===bt).sort((a,b)=>a.date.localeCompare(b.date));
 const days=[...new Set(ms.map(r=>r.date))];
 const mc=r=>{const w=r.sa>r.sb?1:r.sa<r.sb?2:0;return`<div class="mc"><div class="mt ${w===1?"win":w===2?"out":""}"><span>${esc(nm("teams",r.a))}</span><b>${r.sa}</b></div><div class="mt ${w===2?"win":w===1?"out":""}"><span>${esc(nm("teams",r.b))}</span><b>${r.sb}</b></div>${w===0?'<small class="dr">เสมอ</small>':""}</div>`};
 const cols=days.map(d=>`<div class="bc"><div class="bh"><small>วันที่แข่ง</small><b>${fd(d)}</b></div><div class="bm">${ms.filter(r=>r.date===d).map(mc).join("")}</div></div>`).join("");
 const sts=standings(ms).filter(t=>t.p>0);
 const chips=T.map(t=>`<button class="chip ${t.id===bt?"on":""}" data-bt="${t.id}">${esc(t.name)}</button>`).join("");
 return layout(page("bracket-data", {
  tournaments: chips,
  startDate: fd(tr.start),
  place: tr.place?`<span>สถานที่ <b>${esc(tr.place)}</b></span>`:"",
  prize: Number(tr.prize||0).toLocaleString("th-TH"),
  matchCount: ms.length,
  results: ms.length?`<div class="bk" tabindex="0" aria-label="ผลการแข่งขัน เลื่อนดูตามวันที่">${cols}</div><h2 class="sec">ตารางคะแนนรายการนี้</h2><div class="wrap">${rankList(sts)}</div>`:'<div class="wrap"><div class="empty">รายการนี้ยังไม่มีผลการแข่ง</div></div>'
 }));
}

const ADMIN_PW="admin1234";
function setRole(r){role=r;try{sessionStorage.setItem("esm-role",r)}catch(e){}tab="home";location.hash="home";render()}
const banner=()=>`<div class="mode ${role}">${role==="admin"?"โหมดผู้ดูแล — เพิ่ม แก้ไข และลบข้อมูลได้":"โหมดผู้ชม — ดูข้อมูลได้อย่างเดียว"}</div><p class="sub">ข้อมูลตั้งต้นใช้สำหรับสาธิต ข้อมูลที่แก้ไขจัดเก็บใน${connected?"ฐานข้อมูล SQLite":"เบราว์เซอร์นี้"}</p>`;

function loginView(){
 const n=document.getElementById("nav");nav();while(n.children.length>1)n.lastChild.remove();
 document.getElementById("v").innerHTML=page("login", {
  storage: connected?"ฐานข้อมูล SQLite":"เบราว์เซอร์นี้"
 });
}

function render(){if(!role){loginView();return}nav();const v=document.getElementById("v");const f=document.activeElement&&document.activeElement.id==="q";v.innerHTML=banner()+(tab==="home"?home():tab==="player"?playerPage():tab==="compare"?compare():tab==="bracket"?bracket():list(tab));if(f){const i=document.getElementById("q");if(i)i.focus()}}

function field(c,val){const[k,l,ty]=c;let h=`<label for="f_${k}">${l}</label>`;
 if(ty.startsWith("ref")){const src=ty.split(":")[1];h+=`<select id="f_${k}"><option value="">— ไม่ระบุ —</option>${S[src].map(o=>`<option value="${esc(o.id)}" ${o.id===val?"selected":""}>${esc(o.name)}</option>`).join("")}</select>`}
 else if(ty==="img"){IMG[k]=val||"";h+=`<input id="f_${k}" type="file" accept="image/*"><img id="pv_${k}" class="pv" ${val?`src="${esc(val)}"`:"hidden"} alt="ตัวอย่างรูป"><button type="button" class="btn g" id="ri" data-k="${k}">ลบรูปนี้</button>`}
 else if(ty==="ag"){h+=`<input id="f_${k}" placeholder="Jett 28 18 520 390; Raze 16 9 290 240" value="${esc(agStr(val))}"><div style="font-size:12px;color:var(--mute);margin-top:4px">รูปแบบ: ชื่อ เกมที่เล่น ชนะ Kill Death คั่นแต่ละตัวด้วย ;</div>`}
 else if(ty.startsWith("sel")){h+=`<select id="f_${k}">${ty.split(":")[1].split("|").map(o=>`<option ${o===val?"selected":""}>${o}</option>`).join("")}</select>`}
 else h+=`<input id="f_${k}" type="${ty==="num"?"number":ty}" ${ty==="num"?`min="0" step="${k==="sa"||k==="sb"?"1":"any"}" ${k==="sa"||k==="sb"?"required":""}`:""} value="${esc(val??"")}">`;
 return h}

function openForm(id){if(role!=="admin"||saving)return;
 const e=E[tab],r=id?S[tab].find(x=>x.id===id):{};
 const f=document.getElementById("f");
 f.innerHTML=`<h2>${id?"แก้ไข":e.add}</h2>${e.cols.map(c=>field(c,r[c[0]])).join("")}<div id="err" style="color:var(--loss);font-size:14px;margin-top:8px" role="alert"></div><div class="foot"><button class="btn g" type="button" id="cx">ยกเลิก</button><button class="btn" type="button" id="ok">บันทึก</button></div>`;
 document.getElementById("cx").onclick=()=>dlg.close();
 document.getElementById("ok").onclick=async()=>{
   if(saving)return;
  const invalid=f.querySelector(":invalid");if(invalid){invalid.reportValidity();return}
   const o={...r,id:id||uid()};
  for(const c of e.cols){const el=document.getElementById("f_"+c[0]);o[c[0]]=c[2]==="img"?(IMG[c[0]]||""):c[2]==="ag"?pa(el.value):c[2]==="num"?Number(el.value||0):el.value.trim()}
  const first=e.cols[0];
  if(first[2]==="text"&&!o[first[0]])return err("กรุณากรอก"+first[1]);
  if(tab==="results"){if(!o.tour||!o.a||!o.b)return err("กรุณาเลือกรายการแข่งและทีมทั้งสองฝั่ง");if(o.a===o.b)return err("ทีม A และทีม B ต้องไม่ใช่ทีมเดียวกัน");if(!o.date)return err("กรุณาเลือกวันที่แข่ง")}
  if(tab==="players"){
    const entries=document.getElementById("f_agents").value.split(";").map(x=>x.trim()).filter(Boolean);
    const valid=entries.every(x=>{
     const parts=x.split(/\s+/);
     return parts.length===5&&parts.slice(1).every(n=>/^\d+$/.test(n)&&Number.isSafeInteger(Number(n)))&&Number(parts[2])<=Number(parts[1]);
    });
    if(!valid)return err("กรอกสถิติตามรูปแบบตัวอย่าง ใช้จำนวนเต็มตั้งแต่ 0 และจำนวนชนะต้องไม่เกินจำนวนเกม");
   }
   const previous=structuredClone(S);
   if(tab==="gear")ensureLib(o);
  if(id)S[tab]=S[tab].map(x=>x.id===id?o:x);else S[tab].push(o);
  const error=await save(previous);
   if(error){alert(error);return}
   dlg.close();render();
 };
 dlg.showModal();const first=f.querySelector("input,select");if(first)first.focus();
}

const err=m=>{document.getElementById("err").textContent=m};
const dlg=document.getElementById("dlg");

function del(id){delMany([id])}

document.addEventListener("click",ev=>{
 const b=ev.target.closest("button");if(!b){const c=ev.target.closest(".gc[data-e]");if(c)openForm(c.dataset.e);return}
 if(b.dataset.record&&role==="admin"){tab="results";q="";location.hash=tab;render();scrollTo(0,0);openForm()}
  else if(b.dataset.t){tab=b.dataset.t;q="";location.hash=tab;render();scrollTo(0,0)}
 else if(b.dataset.a)openForm();
 else if(b.dataset.e)openForm(b.dataset.e);
 else if(b.dataset.x)del(b.dataset.x);
 else if(b.dataset.pl!==undefined){pl=b.dataset.pl;pt="";render()}
 else if(b.dataset.gt!==undefined){gt=b.dataset.gt;render()}
 else if(b.dataset.bt!==undefined){bt=b.dataset.bt;render()}
 else if(b.id==="sw"){[ca,cb]=[cb,ca];render()}
 else if(b.id==="bd")delMany([...document.querySelectorAll(".rc:checked")].map(c=>c.dataset.id));
 else if(b.id==="ri"){IMG[b.dataset.k]="";const pv=document.getElementById("pv_"+b.dataset.k);if(pv){pv.hidden=true;pv.removeAttribute("src")}}
 else if(b.id==="lo"){role=null;try{sessionStorage.removeItem("esm-role")}catch(e){}tab="home";render()}
 else if(b.id==="lu")setRole("user");
 else if(b.id==="la"){if(document.getElementById("pw").value===ADMIN_PW)setRole("admin");else document.getElementById("le").textContent="รหัสผ่านไม่ถูกต้อง ลองใหม่อีกครั้ง"}
 else if(b.id==="th"){const r=document.documentElement,dark=getComputedStyle(r).getPropertyValue("--bg").trim()==="#10132b";r.dataset.theme=dark?"light":"dark";render()}
});

let qt;document.addEventListener("input",ev=>{if(ev.target.id==="q"){q=ev.target.value;if(ev.isComposing)return;clearTimeout(qt);qt=setTimeout(render,120)}});
document.addEventListener("compositionend",ev=>{if(ev.target.id==="q"){q=ev.target.value;render()}});
addEventListener("hashchange",()=>{const t=location.hash.slice(1);if(t.startsWith("player-")){pid=t.slice(7);tab="player";q="";render();scrollTo(0,0);return}if(t===tab)return;tab=(t==="home"||E[t]||XT.includes(t))?t:"home";q="";render();scrollTo(0,0)});
document.addEventListener("change",ev=>{const t=ev.target;
 if(t.id==="pt"){pt=t.value;render();return}
 if(t.id==="cmpA"){ca=t.value;if(cb===ca)cb=(S.teams.find(x=>x.id!==ca)||{}).id;render();return}
 if(t.id==="cmpB"){cb=t.value;if(ca===cb)ca=(S.teams.find(x=>x.id!==cb)||{}).id;render();return}
 if(t.id==="ca")document.querySelectorAll(".rc").forEach(c=>c.checked=t.checked);
 if(t.id==="ca"||(t.classList&&t.classList.contains("rc"))){const n=document.querySelectorAll(".rc:checked").length,b=document.getElementById("bd");if(b){b.disabled=!n;b.textContent=n?"ลบที่เลือก ("+n+")":"ลบที่เลือก"}}
 if(t.type==="file"&&t.id.startsWith("f_")&&t.files[0]){const k=t.id.slice(2),fr=new FileReader();fr.onload=()=>{const im=new Image();im.onload=()=>{const s=Math.min(1,360/Math.max(im.width,im.height)),c=document.createElement("canvas");c.width=Math.round(im.width*s);c.height=Math.round(im.height*s);c.getContext("2d").drawImage(im,0,0,c.width,c.height);IMG[k]=c.toDataURL("image/jpeg",.82);const pv=document.getElementById("pv_"+k);if(pv){pv.src=IMG[k];pv.hidden=false}};im.src=fr.result};fr.readAsDataURL(t.files[0])}
});
document.addEventListener("keydown",ev=>{if(ev.key==="Enter"&&ev.target.id==="pw")document.getElementById("la").click()});
async function start(){
 if(connected){
  const view=document.getElementById("v");
  view.textContent="กำลังโหลดข้อมูลจากเซิร์ฟเวอร์…";
  try{
   const response=await fetch("/api/state",{cache:"no-store"});
   if(!response.ok)throw Error(response.status);
   const data=await response.json();
   revision=data.revision;
   if(data.state)S=data.state;
  }catch(e){
   view.textContent="โหลดข้อมูลไม่สำเร็จ กรุณาเปิดเซิร์ฟเวอร์ Python แล้วโหลดหน้าใหม่";
   return;
  }
 }
 render();
}
start();
'''


if __name__ == "__main__":
    main()

