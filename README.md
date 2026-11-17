# Self-healing agent

The code that the Self-heal workflow runs when CI fails. Exported from the
research project with `export_agent_repo.py`; do not edit here, edit there
and export again.

    python -m agent.run --repo OWNER/REPO --run-id RUN_ID          # dry run
    python -m agent.run --repo OWNER/REPO --run-id RUN_ID --live   # writes

Needs GITHUB_TOKEN and GOOGLE_API_KEY in the environment.
