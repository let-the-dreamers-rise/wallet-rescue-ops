"""Root-level server entry point for openenv validate compatibility."""

import os

import uvicorn

from wallet_rescue_ops.server.app import app


def main() -> None:
    """Run the FastAPI server."""
    port = int(os.environ.get("PORT", "7860"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
