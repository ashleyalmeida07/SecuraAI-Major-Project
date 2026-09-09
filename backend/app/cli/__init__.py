"""Command-line interface for the AuthTrack security scanners.

The `secura` entry point lives in `app.cli.main`. Nothing is imported here so
that `import app.cli` stays cheap — the graph and its dependencies (LangGraph,
FastEmbed, the Upstash client) are pulled in only when a command actually runs.
"""
