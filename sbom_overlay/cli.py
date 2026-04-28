from pathlib import Path

import click
from rich.console import Console

from sbom_overlay import __version__
from sbom_overlay.support.log import setup_logging

console = Console()


@click.group()
@click.version_option(__version__, prog_name="sbom-overlay")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug-level logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Reconcile a manual SPDX SBOM against a Syft-generated CycloneDX SBOM."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose=verbose, log_dir=Path("logs"))


@cli.command()
@click.option("--manual", "manual", type=click.Path(exists=True, path_type=Path),
              required=True, help="Authoritative SPDX 2.3 JSON SBOM.")
@click.option("--syft", "syft", type=click.Path(exists=True, path_type=Path),
              required=True, help="Syft-generated CycloneDX 1.5 JSON SBOM.")
@click.option("--name", "name", required=True,
              help="Product name + version, e.g. 'affinity-5.0.0'.")
@click.option("--output-dir", "output_dir", type=click.Path(path_type=Path),
              default=Path("artifacts"), show_default=True, help="Where to write the report.")
def reconcile(manual: Path, syft: Path, name: str, output_dir: Path) -> None:
    """Compare two SBOMs and write a reconciliation report."""
    del manual, syft, name, output_dir  # silence unused until implemented
    console.print("[yellow][!][/yellow] reconcile is not implemented yet")
    raise click.exceptions.Exit(code=1)
