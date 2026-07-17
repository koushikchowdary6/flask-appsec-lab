"""Local entrypoint. Binds to 127.0.0.1 only -- this app must never be
exposed on a public interface (the /vuln routes are exploitable by design)."""
from app import create_app

if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
