"""FuzzySully CLI"""

# builtin-imports
from pathlib import Path

# Third-party imports
import rich_click as click
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel

# Local imports
from fuzzysully import FuzzySully, OPCUAMode, OPCUASupportedPolicies
from fuzzysully import __version__ as fuzzysully_version

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "show_default": True}

click.rich_click.MAX_WIDTH = 120
click.rich_click.USE_RICH_MARKUP = True
click.rich_click.OPTION_GROUPS = {
    "fuzzysully": [
        {"name": "Global options", "options": ["--help", "--version"]},
        {"name": "Fuzzer Options", "options": ["--function", "--list-functions"]},
        {
            "name": "OPCUA Options",
            "options": [
                "--app-uri",
                "--policy",
                "--client-cert",
                "--private-key",
                "--private-key-password",
                "--server-cert",
                "--encrypt",
                "--username",
                "--password",
            ],
        },
        {
            "name": "Connection Options",
            "options": [
                "--bind",
                "--send-timeout",
                "--recv-timeout",
                "--sleep-time",
                "--new-conns",
                "--transmit-full-path",
            ],
        },
        {
            "name": "RECV() Options",
            "options": ["--no-recv", "--no-recv-fuzz", "--check-recv"],
        },
        {
            "name": "Crashes Options",
            "options": [
                "--threshold-request",
                "--threshold-element",
            ],
        },
    ]
}


def print_functions(ctx: click.Context, param: click.Parameter, value):
    """Display list of available functions and exist (click callback)"""
    if not value or ctx.resilient_parsing:
        return
    console = Console()
    funcs_renderables = []
    for m in OPCUAMode.__members__.values():
        funcs = FuzzySully.list_available_functions(m)
        funcs.sort()
        render = f"[b]{m} mode[/b]"
        for f in funcs:
            render += f"\n[yellow]{f}"
        funcs_renderables.append(render)
    console.print(Columns([Panel(mode, expand=True) for mode in funcs_renderables]))

    ctx.exit()


# If no default value is provided, the default value is None.
@click.command(context_settings=CONTEXT_SETTINGS)
@click.version_option(fuzzysully_version)
# connection options
@click.option("-b", "--bind", type=int, help="Bind to port.")
@click.option(
    "-st",
    "--send-timeout",
    type=float,
    default=1.0,
    help="Set send() timeout.",
)
@click.option(
    "-rt",
    "--recv-timeout",
    type=float,
    default=1.0,
    help="Set recv() timeout.",
)
@click.option(
    "--sleep-time",
    type=float,
    default=0.0,
    help="Sleep time between each test.",
)
@click.option(
    "-nc",
    "--new-conns",
    is_flag=True,
    help="Open a new connection after each packet of the same test.",
)
@click.option(
    "-tn",
    "--transmit-full-path",
    is_flag=True,
    help="Transmit the next node in the graph of the fuzzed node.",
)
# recv options
@click.option(
    "-nr",
    "--no-recv",
    is_flag=True,
    help="Do not recv() in the socket after each send.",
)
@click.option(
    "-nrf",
    "--no-recv-fuzz",
    is_flag=True,
    help="Do not recv() in the socket after sending a fuzzed request.",
)
@click.option(
    "-cr",
    "--check-recv",
    is_flag=True,
    help="Check that data has been received in recv().",
)
# crashes options
@click.option(
    "--threshold-request",
    "crash_threshold_request",
    type=int,
    default=9999,
    help="Set the number of allowed crashes in a Request before skipping it.",
)
@click.option(
    "--threshold-element",
    "crash_threshold_element",
    type=int,
    default=9999,
    help="Set the number of allowed crashes in a Primitive before skipping it.",
)
# OPCUA options
@click.option(
    "--policy",
    "security_policy",
    type=click.Choice(OPCUASupportedPolicies, case_sensitive=False),
    default=OPCUASupportedPolicies.NONE,
    help="Set the security policy to use for OPCUA messages. \
Basic256Sha256 policy requires --client-cert and --private-key to be set.",
)
@click.option(
    "--client-cert",
    "client_cert_path",
    # check that the path exists, is a file and convert it to a Path object
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    help="Set the client certificate path to use for authentication.",
)
@click.option(
    "--private-key",
    "private_key_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    help="Set the client private key path to use for authentication.",
)
@click.option(
    "--private-key-password",
    "private_key_pwd",
    type=str,
    help="Set the client private key password (if required).",
)
@click.option(
    "--app-uri",
    "app_uri",
    type=str,
    default="urn:S2OPC:localhost",
    help="Set OPCUA client application URI (must match the client certificate SAN value).",
)
@click.option(
    "--encrypt",
    "encrypt",
    is_flag=True,
    help="Enable SignAndEncrypt mode (default mode is Sign).",
)
@click.option(
    "-u",
    "--username",
    "username",
    type=str,
    default=None,
    help="Set OPCUA username to use for user authentication.",
)
@click.option(
    "-p",
    "--password",
    "password",
    type=str,
    default=None,
    help="Set OPCUA password to use for user authentication.",
)
# fuzzer options
@click.option(
    "-f",
    "--function",
    "functions",
    type=str,
    multiple=True,
    # lower the str to uniformize names
    callback=(lambda ctx, param, value: [v.lower() for v in value]),
    help="""
Specify specific functions to fuzz, it can be specified multiple time. 
By default it will fuzz all the functions available for the chosen mode. 
For a list of all the functions available see --list-functions.""",
)
@click.option(
    "--list-functions",
    is_flag=True,
    callback=print_functions,
    is_eager=True,
    expose_value=False,
    help="List all the functions that can be fuzzed.",
)
@click.argument("mode", type=click.Choice(OPCUAMode, case_sensitive=False))
@click.argument("host", type=str, metavar="<destination host>")
@click.argument("port", type=int, metavar="<destination port>")
@click.argument("d_path", type=str, metavar="<destination d_path>")
def main(
    mode,
    host,
    port,
    d_path,
    bind,
    send_timeout,
    recv_timeout,
    sleep_time,
    new_conns,
    transmit_full_path,
    no_recv,
    no_recv_fuzz,
    check_recv,
    crash_threshold_request,
    crash_threshold_element,
    security_policy,
    client_cert_path,
    private_key_path,
    private_key_pwd,
    app_uri,
    encrypt,
    username,
    password,
    functions,
):
    """
    FuzzySully is a fuzzer for OPCUA implementations based on Fuzzowski fuzzer.

    It can fuzz three OPCUA modes: a server providing OPCUA services ([b cyan]server[/]),
    a reverse client ([b cyan]reverse[/]) and a Global Discovery Service Server ([b cyan]gds[/]).

    - Server mode supports both None and Basic256Sha256 policies.

    - Reverse mode handles None policy.

    - GDS requires Basic256Sha256 policy with encryption.

    By default, it will fuzz all the functions available for the selected mode. To personalize it,
    use `-f` option.
    """
    # post-process linked options
    if mode == OPCUAMode.GDS and (
        not encrypt or security_policy == OPCUASupportedPolicies.NONE
    ):
        raise click.BadArgumentUsage(
            f"Missing option(s): '{OPCUAMode.GDS}' mode requires the following options to be set: \
'--encrypt' and '--policy {OPCUASupportedPolicies.BASIC_SHA}'."
        )

    if security_policy == OPCUASupportedPolicies.BASIC_SHA:
        if client_cert_path is None or private_key_path is None:
            raise click.BadOptionUsage(
                "security_policy",
                f"Missing option(s): '{OPCUASupportedPolicies.BASIC_SHA}' security policy \
requires --client-cert and --private-key options to be set.",
            )

    if encrypt:  # encryption require basic SHA, signature options already check before
        if security_policy != OPCUASupportedPolicies.BASIC_SHA:
            raise click.BadOptionUsage(
                "encrypt",
                f"Missing option(s): '--encrypt' requires the following \
options to be set: --client-cert, --private-key and '--policy {OPCUASupportedPolicies.BASIC_SHA}'.",
            )

    if (username and not password) or (not username and password):
        raise click.BadOptionUsage(
            "username",
            "Missing option: \
'--username' and '--password' must both be set.",
        )

    # check functions exist
    for f in functions:
        if f not in FuzzySully.list_available_functions(mode):
            raise click.BadOptionUsage(
                "functions",
                f"Bad option: the function '{f}' does not exists for the '{mode}' mode. Use --list-functions \
to show all the available functions.",
            )

    # instantiate fuzzer
    fuzzer = FuzzySully(
        mode=mode,
        host=host,
        port=port,
        d_path=d_path,
        bind=bind,
        send_timeout=send_timeout,
        recv_timeout=recv_timeout,
        sleep_time=sleep_time,
        new_conns=new_conns,
        transmit_full_path=transmit_full_path,
        no_recv=no_recv,
        no_recv_fuzz=no_recv_fuzz,
        check_recv=check_recv,
        crash_threshold_request=crash_threshold_request,
        crash_threshold_element=crash_threshold_element,
        policy=security_policy,
        client_cert_path=client_cert_path,
        private_key_path=private_key_path,
        private_key_pwd=private_key_pwd,
        app_uri=app_uri,
        encrypt=encrypt,
        username=username,
        password=password,
        fuzz_requests=functions,
    )
    fuzzer.run()


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
