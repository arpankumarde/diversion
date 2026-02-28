"""Tests for codebase cross-reference."""

import tempfile
from pathlib import Path

from nazitest.analysis.codebase_xref import CodebaseXRef


class TestCodebaseXRef:
    def _make_project(self, tmpdir: str) -> Path:
        root = Path(tmpdir) / "project"
        root.mkdir()

        # Express routes
        (root / "app.js").write_text(
            """
const express = require('express');
const app = express();
app.get('/api/users', (req, res) => { res.json([]); });
app.post('/api/login', (req, res) => {
    db.query('SELECT * FROM users WHERE name=' + req.body.name);
});
app.delete('/api/users/:id', (req, res) => { res.send('ok'); });
"""
        )

        # Flask routes
        (root / "views.py").write_text(
            """
from flask import Flask
app = Flask(__name__)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return render('dashboard.html')

@app.route('/search')
def search():
    query = request.args.get('q')
    cursor.execute("SELECT * FROM items WHERE name LIKE '%" + query + "%'")
"""
        )

        # package.json for dep detection
        (root / "package.json").write_text('{"dependencies": {"express": "4.18.0"}}')

        return root

    def test_extract_express_routes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = self._make_project(tmpdir)
            xref = CodebaseXRef()
            result = xref.analyze(root)

            express_routes = [r for r in result.routes if r.framework == "express"]
            paths = {r.path for r in express_routes}
            assert "/api/users" in paths
            assert "/api/login" in paths

    def test_extract_flask_routes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = self._make_project(tmpdir)
            xref = CodebaseXRef()
            result = xref.analyze(root)

            flask_routes = [r for r in result.routes if r.framework == "flask"]
            paths = {r.path for r in flask_routes}
            assert "/dashboard" in paths
            assert "/search" in paths

    def test_find_dangerous_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = self._make_project(tmpdir)
            xref = CodebaseXRef()
            result = xref.analyze(root)

            sink_types = {s.sink_type for s in result.sink_flows}
            assert "sql" in sink_types  # db.query and cursor.execute
            assert "template" in sink_types  # render()

    def test_find_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = self._make_project(tmpdir)
            xref = CodebaseXRef()
            result = xref.analyze(root)

            managers = {d["manager"] for d in result.dependencies}
            assert "npm" in managers

    def test_nonexistent_path(self) -> None:
        xref = CodebaseXRef()
        result = xref.analyze("/nonexistent/path")
        assert result.routes == []
        assert result.sink_flows == []
