"""Root-level server entry point for openenv validate compatibility."""

from wallet_rescue_ops.server.app import app, main

__all__ = ["app", "main"]

if __name__ == "__main__":
    main()
