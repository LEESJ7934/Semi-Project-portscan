"""Loopback-only fake banner server. It does not implement an Apache vulnerability."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.50"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Portscanner-Demo", "simulated-banner-only")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        body = b"PortScanner Day 4: simulated banner only, not an Apache installation.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Portscanner-Demo", "simulated-banner-only")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--version", choices=["2.4.50", "2.4.51"], default="2.4.50")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    DemoHandler.server_version = "Apache/" + args.version
    try:
        with ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler) as server:
            print(f"Demo: http://127.0.0.1:{args.port} (simulated {DemoHandler.server_version})", flush=True)
            print("Banner only; no vulnerable Apache code. Stop with Ctrl+C.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    except OSError as exc:
        parser.exit(1, f"Cannot start demo server: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
