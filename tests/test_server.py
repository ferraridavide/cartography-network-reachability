import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from cartography_reachability.server import create_app


class FakeBuilder:
    def __init__(self, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("Neo4j unavailable")
        return {"nodes": [], "edges": [], "path_count": self.calls}


class ServerApiTest(unittest.TestCase):
    def test_bundle_is_traced_once_and_cached(self):
        builder = FakeBuilder()
        client = TestClient(create_app(builder, web_dir=None))

        first = client.get("/api/bundle")
        second = client.get("/api/bundle")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.json()["path_count"], 1)
        self.assertEqual(builder.calls, 1)
        self.assertEqual(first.json()["meta"]["source"], "neo4j")
        self.assertIn("generated_at", first.json()["meta"])

    def test_refresh_traces_again(self):
        builder = FakeBuilder()
        client = TestClient(create_app(builder, web_dir=None))

        client.get("/api/bundle")
        refreshed = client.get("/api/bundle?refresh=1")

        self.assertEqual(refreshed.json()["path_count"], 2)
        self.assertEqual(builder.calls, 2)

    def test_trace_failure_returns_error_message(self):
        client = TestClient(create_app(FakeBuilder(fail=True), web_dir=None))

        response = client.get("/api/bundle")
        status = client.get("/api/status").json()

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {"error": "Neo4j unavailable"})
        self.assertEqual(status["error"], "Neo4j unavailable")
        self.assertFalse(status["ready"])

    def test_status_reports_connection_without_password(self):
        connection = {"uri": "bolt://db:7687", "user": "neo4j", "password_set": True}
        client = TestClient(create_app(FakeBuilder(), web_dir=None, connection=connection))

        status = client.get("/api/status").json()

        self.assertEqual(status["connection"], connection)
        self.assertFalse(status["running"])


class ServerStaticTest(unittest.TestCase):
    def test_serves_frontend_with_spa_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            web_dir = Path(tmp)
            (web_dir / "index.html").write_text("<html>app</html>")
            (web_dir / "assets").mkdir()
            (web_dir / "assets" / "app.js").write_text("console.log('ok')")
            client = TestClient(create_app(FakeBuilder(), web_dir=web_dir))

            self.assertEqual(client.get("/").text, "<html>app</html>")
            self.assertEqual(client.get("/assets/app.js").text, "console.log('ok')")
            self.assertEqual(client.get("/rays/outbound/eni:eni-1").text, "<html>app</html>")
            self.assertEqual(client.get("/api/bundle").status_code, 200)

    def test_missing_frontend_explains_how_to_build(self):
        client = TestClient(create_app(FakeBuilder(), web_dir=Path("/nonexistent")))

        response = client.get("/")

        self.assertEqual(response.status_code, 503)
        self.assertIn("npm run build", response.text)


if __name__ == "__main__":
    unittest.main()
