import io
import tarfile
import zipfile
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[2] / "scanner-fixtures" / "projects"


def zip_directory(name: str, prefix: str = "repo/") -> bytes:
    root = FIXTURES / name
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                archive.write(path, prefix + path.relative_to(root).as_posix())
    return buffer.getvalue()


def zip_members(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def tar_with(members) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def create_upload_project(client, name="Payments API"):
    response = client.post(f"/api/v1/organizations/{client.org_id}/projects", json={"name": name, "source_type": "upload"})
    assert response.status_code == 201, response.text
    return response.json()


def upload_and_scan(client, project_id, data: bytes, filename="source.zip"):
    response = client.post(
        f"/api/v1/organizations/{client.org_id}/projects/{project_id}/scans/upload",
        files={"file": (filename, data, "application/zip")},
    )
    assert response.status_code == 202, response.text
    return response.json()


def run_worker():
    from app.v1.worker import run_pending_once

    return run_pending_once("test-worker")
