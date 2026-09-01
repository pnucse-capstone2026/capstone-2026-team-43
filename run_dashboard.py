from __future__ import annotations

import argparse

import uvicorn
from dotenv import load_dotenv


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Host DLP dashboard securely.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--ssl-certfile")
    parser.add_argument("--ssl-keyfile")
    args = parser.parse_args()

    load_dotenv(args.env_file)

    from backend import main as backend

    backend.validate_server_security(args.host, args.ssl_certfile, args.ssl_keyfile)
    backend.app.state.security_validated = True
    uvicorn.run(
        backend.app,
        host=args.host,
        port=args.port,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
    )


if __name__ == "__main__":
    main()
