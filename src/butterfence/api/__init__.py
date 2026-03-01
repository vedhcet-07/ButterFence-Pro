"""ButterFence REST API — FastAPI application factory."""

from __future__ import annotations

from pathlib import Path


def create_app(project_dir: Path | None = None):
    """Create and configure the FastAPI application.

    Args:
        project_dir: Root directory of the project to operate on.
                     Defaults to current working directory.
    """
    try:
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import FileResponse, HTMLResponse
    except ImportError:
        raise ImportError(
            "FastAPI is required for the API server. "
            "Install with: pip install butterfence[api]"
        )

    if project_dir is None:
        project_dir = Path.cwd()

    app = FastAPI(
        title="ButterFence Pro API",
        description="Security-first tool-use defense layer for AI coding agents",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Store project_dir in app state
    app.state.project_dir = project_dir

    # Register API routes
    from butterfence.api.routes import router
    app.include_router(router, prefix="/api")

    # Dashboard static directory
    dashboard_dir = Path(__file__).parent.parent / "dashboard"

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "butterfence-api"}

    @app.get("/dashboard/{filename}")
    async def dashboard_static(filename: str):
        """Serve dashboard static files."""
        file_path = dashboard_dir / filename
        if file_path.exists() and file_path.is_file():
            content_types = {
                ".html": "text/html",
                ".css": "text/css",
                ".js": "application/javascript",
                ".json": "application/json",
                ".png": "image/png",
                ".svg": "image/svg+xml",
            }
            ct = content_types.get(file_path.suffix, "application/octet-stream")
            return FileResponse(file_path, media_type=ct)
        return HTMLResponse("<h1>Not Found</h1>", status_code=404)

    @app.get("/dashboard")
    async def dashboard_index():
        """Serve the main dashboard page."""
        index = dashboard_dir / "index.html"
        if index.exists():
            return FileResponse(index, media_type="text/html")
        return HTMLResponse(
            "<h1>Dashboard not found</h1>"
            "<p>Dashboard files not installed.</p>",
            status_code=404,
        )

    return app

