
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router, workspace_relative_path
from security_engine.scanner.watcher import SourceFileWatcher


# Keep the watched directory inside the backend workspace.
BACKEND_DIR = (
    Path(__file__).resolve().parent
    / "api"
    / "docs"
    / "security-demo"
)

watcher_state = {
    "running": False,
    "last_file": None,
    "last_findings": [],
    "last_error": None,
}
watcher_lock = Lock()
watcher = None


def handle_file_change(filename, findings):
    """Store the latest result produced by the file watcher."""
    with watcher_lock:
        watcher_state["last_file"] = str(filename)
        watcher_state["last_findings"] = findings
        watcher_state["last_error"] = None


def handle_file_scan_error(filename, error):
    """Expose watcher failures without presenting them as clean results."""
    with watcher_lock:
        watcher_state["last_file"] = str(filename)
        watcher_state["last_findings"] = []
        watcher_state["last_error"] = (
            f"Source file scan failed ({type(error).__name__})."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global watcher

    watcher = SourceFileWatcher(
        root=BACKEND_DIR,
        on_change=handle_file_change,
        on_error=handle_file_scan_error,
        interval=1.0,
        debounce=0.5,
    )
    watcher.start()

    with watcher_lock:
        watcher_state["running"] = True

    try:
        yield
    finally:
        watcher.stop()

        with watcher_lock:
            watcher_state["running"] = False

        watcher = None


app = FastAPI(
    title="SecurCode Security API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.include_router(router)


@app.get("/")
def root():
    return {"message": "SecurCode API is running"}


@app.get("/watcher/status")
def get_watcher_status():
    with watcher_lock:
        return {
            "running": watcher_state["running"],
            "last_file": (
                workspace_relative_path(watcher_state["last_file"])
                if watcher_state["last_file"]
                else None
            ),
            "last_findings_count": len(watcher_state["last_findings"]),
            "last_error": watcher_state["last_error"],
        }


@app.get("/watcher/findings")
def get_watcher_findings():
    with watcher_lock:
        return {
            "last_file": (
                workspace_relative_path(watcher_state["last_file"])
                if watcher_state["last_file"]
                else None
            ),
            "total_findings": len(watcher_state["last_findings"]),
            "findings": watcher_state["last_findings"],
            "error": watcher_state["last_error"],
        }
