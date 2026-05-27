import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

app = typer.Typer(name="svault", help="AI-aware secret access layer", add_completion=False)
console = Console()


@app.command()
def init():
    """Initialize encrypted vault and set master passphrase."""
    console.print("[bold green]svault init[/] — coming soon")


@app.command()
def unlock():
    """Unlock the vault daemon."""
    console.print("[bold green]svault unlock[/] — coming soon")


@app.command()
def lock():
    """Lock the vault daemon."""
    console.print("[yellow]svault lock[/] — coming soon")


@app.command()
def install(
    platform: str = typer.Option("auto", help="AI platform: claude, cursor, codex, copilot, aider"),
    project: bool = typer.Option(False, "--project", help="Project-scoped install (git-committable)"),
):
    """Wire Svault into your AI platform."""
    console.print(f"[bold green]svault install[/] --platform {platform} — coming soon")


@app.command()
def get(
    name: str = typer.Argument(..., help="Secret name"),
    scope: str = typer.Option(..., help="Access scope e.g. coolify:deploy"),
    reason: str = typer.Option(..., help="Why you need this secret right now"),
):
    """Request a secret (structured — reason required)."""
    console.print(f"[bold]Requesting:[/] {name}")
    console.print(f"  scope:  {scope}")
    console.print(f"  reason: {reason}")
    console.print("[yellow]— coming soon[/]")


@app.command()
def version():
    """Show version."""
    from svault import __version__
    console.print(f"[bold]svault[/] {__version__}")


if __name__ == "__main__":
    app()
