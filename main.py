"""Root launcher for the SOAR Lite API."""

from soar_lite.main import app

__all__ = ["app"]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("soar_lite.main:app", reload=True)
