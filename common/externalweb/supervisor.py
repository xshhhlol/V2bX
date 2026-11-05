"""Private V2bX child supervisor; no shell, host service edits or downloads."""
import hashlib
import ipaddress
import json
import os
import pwd
import re
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time


def quote(value):
    value = str(value)
    if any(ord(c) < 32 for c in value):
        raise ValueError("control character in frontend configuration")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$') + '"'


def atomic(path, data, mode=0o600):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as output:
        os.chmod(temporary, mode)
        output.write(data if isinstance(data, bytes) else data.encode())
    temporary.replace(path)


def render(directory, manifest):
    """Only trusted local manifest fields enter configs; all paths are quoted."""
    directory = Path(directory)
    (directory / "logs").mkdir(exist_ok=True)
    site = directory / "site"
    site.mkdir(exist_ok=True)
    (site / "index.html").write_text("<!doctype html><html><title>Home</title><body><h1>Home</h1></body></html>\n")
    nginx = [f"pid {quote(directory / 'nginx.pid')};", "worker_processes auto;",
             "error_log stderr warn;", "events { worker_connections 2048; }", "http {",
             "access_log off; server_tokens off; default_type application/octet-stream;",
             "types { text/html html; text/css css; application/javascript js; image/png png; image/jpeg jpg jpeg; image/svg+xml svg; }",
             "client_header_timeout 30s; keepalive_timeout 120s; send_timeout 120s;",
             *[f"{kind}_temp_path {quote(directory / ('temp_' + kind))};" for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")],
             "map $host $v2bx_https { hostnames; default $host;"]
    domains = {}
    for node in sorted(manifest["nodes"], key=lambda n: n["tag"]):
        domain = node.get("domain", "")
        if domain and re.fullmatch(r"(?:\*\.)?[a-zA-Z0-9.-]+", domain):
            if domain not in domains or int(node["port"]) == 443:
                domains[domain] = node["port"]
    nginx += [f"{domain} $host" + (f":{int(port)};" if int(port) != 443 else ";") for domain, port in domains.items()]
    nginx += ["}", "server {", f"listen {manifest.get('http_listen') or '0.0.0.0:80'};",
             "location ^~ /.well-known/acme-challenge/ {",
             f"proxy_pass http://{manifest['acme']};", "proxy_set_header Host $http_host;",
             "proxy_buffering off; proxy_request_buffering off;",
             "proxy_intercept_errors on; error_page 400 404 405 = @challenge_missing;", "}",
             "location @challenge_missing { return 404; }",
             "location / { return 308 https://$v2bx_https$request_uri; }", "}"]
    haproxy = ["global", "  maxconn 8192", "  ssl-default-bind-options ssl-min-ver TLSv1.2",
               "defaults", "  mode tcp", "  timeout connect 5s", "  timeout client 5m",
               "  timeout server 5m"]
    if os.geteuid() == 0:
        try:
            account = pwd.getpwnam("haproxy")
            haproxy[1:1] = [f"  uid {account.pw_uid}", f"  gid {account.pw_gid}"]
        except KeyError:
            raise RuntimeError("the haproxy system account is missing; reinstall the distribution haproxy package")
    fingerprints = []
    ports = []
    for node in sorted(manifest["nodes"], key=lambda n: n["tag"]):
        key = hashlib.sha256(node["tag"].encode()).hexdigest()[:16]
        address = ipaddress.ip_address(node["listen"])
        bind = f"[{address}]:{int(node['port'])}" if address.version == 6 else f"{address}:{int(node['port'])}"
        cert, private = Path(node["certificate"]).read_bytes(), Path(node["key"]).read_bytes()
        # Wait until a rotated certificate and key form a matching pair.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(node["certificate"], node["key"])
        pem = directory / (key + ".pem")
        atomic(pem, cert + b"\n" + private)
        fingerprints.append(hashlib.sha256(cert + private).hexdigest())
        root = Path(node["root"]).resolve() if node["root"] else site
        if not root.is_dir():
            raise ValueError("external website root does not exist: " + str(root))
        for protocol, port in [("", node["http1"]), (" http2", node["http2"])]:
            nginx += ["server {", f"listen 127.0.0.1:{int(port)}{protocol};", f"root {quote(root)};",
                      "index index.html; autoindex off; log_not_found off;", "location ~ (^|/)\\. { return 404; }", "}"]
            ports.append(("127.0.0.1", int(port)))
        strict = " strict-sni" if node["reject_unknown_sni"] else ""
        # send-proxy-v2 automatically includes negotiated ALPN. TCP mode
        # leaves both valid Trojan and HTTP/2 payloads untouched after TLS.
        haproxy += [f"frontend fe_{key}", f"  bind {bind} ssl crt {quote(pem)} alpn h2,http/1.1{strict}",
                    f"  default_backend be_{key}", f"backend be_{key}",
                    f"  server v2bx 127.0.0.1:{int(node['backend'])} send-proxy-v2"]
    nginx.append("}")
    return "\n".join(nginx) + "\n", "\n".join(haproxy) + "\n", fingerprints, ports


class Supervisor:
    def __init__(self, directory):
        self.directory = Path(directory)
        search = os.environ.get("PATH", "") + os.pathsep + "/usr/sbin:/usr/bin:/sbin:/bin"
        self.nginx = shutil.which("nginx", path=search)
        self.haproxy = shutil.which("haproxy", path=search)
        if not self.nginx or not self.haproxy:
            raise RuntimeError("nginx and haproxy are required; install them using the V2bX configuration wizard")
        self.children = {}
        self.fingerprints = []

    def command(self, name):
        if name == "nginx":
            return [self.nginx, "-e", "stderr", "-p", str(self.directory) + "/", "-c", str(self.directory / "nginx.conf")]
        return [self.haproxy, "-f", str(self.directory / "haproxy.cfg")]

    def apply(self, manifest):
        nginx, haproxy, fingerprints, ports = render(self.directory, manifest)
        atomic(self.directory / "nginx.conf", nginx)
        atomic(self.directory / "haproxy.cfg", haproxy)
        for name in ("nginx", "haproxy"):
            result = subprocess.run(self.command(name) + (["-t"] if name == "nginx" else ["-c"]),
                                    capture_output=True, text=True, timeout=10)
            if result.returncode:
                raise RuntimeError(name + " configuration rejected: " + result.stderr[-3000:] + result.stdout[-3000:])
        for name in ("nginx", "haproxy"):
            process = self.children.get(name)
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGHUP if name == "nginx" else signal.SIGUSR2)
            else:
                arguments = ["-g", "daemon off;"] if name == "nginx" else ["-W", "-db"]
                self.children[name] = subprocess.Popen(self.command(name) + arguments, start_new_session=True)
        # Acknowledge only after child processes stay alive and the website
        # listeners accept connections. The public listeners are also checked.
        ports += [(n["listen"] if n["listen"] not in ("0.0.0.0", "::") else ("127.0.0.1" if n["listen"] == "0.0.0.0" else "::1"), int(n["port"])) for n in manifest["nodes"]]
        deadline = time.monotonic() + 5
        while True:
            if any(p.poll() is not None for p in self.children.values()):
                raise RuntimeError("external frontend exited during startup; check the service log for port conflicts")
            try:
                for host, port in ports:
                    with socket.create_connection((host, port), timeout=.2):
                        pass
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("external frontend listeners did not become ready")
                time.sleep(.1)
        self.fingerprints = fingerprints

    def close(self):
        for process in self.children.values():
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for process in self.children.values():
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def main(directory):
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    supervisor = None
    generation = None
    manifest = None
    next_check = 0
    try:
        while not stopping:
            path = Path(directory)
            try:
                candidate = json.loads((path / "manifest.json").read_text())
                changed = candidate["generation"] != generation
                if supervisor is None:
                    supervisor = Supervisor(directory)
                dead = any(p.poll() is not None for p in supervisor.children.values())
                rotate = False
                if not changed and time.monotonic() >= next_check:
                    next_check = time.monotonic() + 5
                    fingerprints = [hashlib.sha256(Path(n["certificate"]).read_bytes() + Path(n["key"]).read_bytes()).hexdigest()
                                    for n in sorted(candidate["nodes"], key=lambda n: n["tag"])]
                    rotate = fingerprints != supervisor.fingerprints
                if changed or dead or rotate:
                    supervisor.apply(candidate)
                    manifest, generation = candidate, candidate["generation"]
                    atomic(path / "status.json", json.dumps({"generation": generation, "error": ""}))
            except FileNotFoundError:
                pass
            except Exception as error:
                print("external web:", error, file=sys.stderr, flush=True)
                if 'candidate' in locals():
                    atomic(path / "status.json", json.dumps({"generation": candidate["generation"], "error": str(error)}))
                    generation = candidate["generation"]
                time.sleep(1)
            time.sleep(.25)
    finally:
        if supervisor:
            supervisor.close()


if __name__ == "__main__":
    main(sys.argv[1])
