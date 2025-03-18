FuzzySully - Fuzzowski-based OPCUA fuzzer
=========================================
   
Introduction
------------
<span style="color:red">**Fuzzing should never be conducted on production equipment or systems. This testing technique can cause unexpected behavior, system crashes, data corruption, or security vulnerabilities. Always perform fuzzing in a controlled, isolated environment to ensure the safety and stability of production systems.**</span>

FuzzySully is an OPC UA fuzzer built upon Fuzzowski. It is a specialized testing tool designed to identify vulnerabilities and bugs in OPC UA (Open Platform Communications Unified Architecture) implementations. These fuzzers typically operate by generating and sending a large number of malformed or unexpected messages to an OPC UA server or client, with the goal of triggering unexpected behavior or crashes.

Security
-----

See [SECURITY.md](SECURITY.md)

Contributing
-----

See [CONTRIBUTING.md](CONTRIBUTING.md)


Setup
-----
FuzzySully is a Python package. It requires at least Python 3.10. 

1. Create a virtual environment: `python3 -m venv fuzzysully-venv`
2. Activate your virtual environment: `. ./fuzzysully-venv/bin/activate`
3. Install FuzzySully from the project directory: `pip install .`

Command-line options
--------------------

This section summarizes the command-line options supported by FuzzySully.

It can fuzz :
- `client` (reverse mode) ;
- `server` (server mode) providing OPCUA services ;
- `Global Discovery Server` (gds mode).

 The general command usage is :
```commandline
fuzzysully [OPTIONS] {gds|server|reverse} <destination host> <destination port> "<destination path>" 
```
Where :
- **host**: The server's hostname or IP address ;
- **port**: The port number on which the OPC UA server is listening ;
- **path**: Additional path information, if required.

Most OPC UA endpoints use the simpler format without a path: *opc.tcp://host:port*

*Example:* `opc.tcp://192.168.1.100:4840`

In some cases, a path is necessary: *opc.tcp://host:port/path*

*Example:* `opc.tcp://192.168.1.100:4840/UA/MyApplication`

**Note:** The inclusion of a path depends on the specific OPC UA server configuration.

### Fuzzer options

- `--function`, `-f`: specify specific functions to fuzz, multiple functions can be specified. By default, it  will fuzz all the functions available for the chosen mode.

-  `--list-functions`: list all the functions that can be fuzzed

    The following fuzzysully functions are currently supported :
    > 
    >   | `gds` mode                                | `server` mode                     | `reverse` mode |
    >   |-------------------------------------------|-----------------------------------|----------------| 
    >   | finish_request                            | add_nodes                         | reverse_hello  |
    >   | finish_request_start_new_key_pair_request | browse                            |                |
    >   | finish_request_start_signing_request      | browse_next                       |                |
    >   | get_certificate_groups                    | create_monitor                    |                |
    >   | get_certificate_status                    | create_subscription               |                |
    >   | get_trust_list                            | delete_monitor                    |                |
    >   | revoke_certificate                        | find_server                       |                |
    >   | start_new_key_pair_request                | find_server_on_network            |                |
    >   | start_signing_request                     | get_endpoints                     |                |
    >   |                                           | hello                             |                | 
    >   |                                           | history_read                      |                |
    >   |                                           | modify_monitor                    |                |
    >   |                                           | publish                           |                |
    >   |                                           | read                              |                |
    >   |                                           | register_nodes                    |                |
    >   |                                           | register_server2                  |                |
    >   |                                           | secure_channel                    |                |
    >   |                                           | session                           |                |
    >   |                                           | translate_browse_path_to_node_ids |                |
    >   |                                           | unregister_nodes                  |                |

Some of these functions can handle mutliples OPCUA services. For instance, the `session` function include `CreateSession`, `ActivateSession`, `CloseSession`.


### OPCUA options

- `--app-uri`: set the OPCUA application URI to use for fuzzing (must match the client certificate SAN value, default: `urn:S2OPC:localhost`)
- `--policy`: set the security policy to use for OPCUA messages. Requires `--client-cert` and `--private-key` to be set (default: `None`)
    - `fuzzysully` currently supports the security policies `None` and `Basic256Sha256`. 
    - `gds` mode has to use the `Basic256Sha256` policy.
    - `server` mode could use both of them, but with `Basic256Sha256`, this mode does not handle the following functions: `hello`, `secure_channel`, `session`.
    - `reverse` mode has only been implemented for the `None` security policy.
- `--client-cert`: set the client certificate path to use for the application authentication
- `--private-key`: set the client private key path to use for the application authentication
- `--private-key-password`: set the client private key password (if required)
- `--encrypt`: enable `SignAndEncrypt` mode (default mode is `Sign`), this mode is mandatory to fuzz a GDS
- `--username`, `-u`: set OPCUA username to use for user authentication
- `--password`, `-p`: set OPCUA password to use for user authentication


### Connection options
- `--send-timeout`, `-st`: set transmit timeout in seconds (default: `1.0`, accepts floating point values)
- `--recv-timeout`, `-rt`: set reception timeout in seconds (default: `1.0`, accepts floating point values)
- `--sleep-time`: sleep time between each test, in seconds (default: `0.0`, accepts floating point values)
- `--transmit-full-path`, `-tn`: transmit the next node in the graph of the fuzzed node

### Receive options

- `--no-recv`, `-nr`: do not wait for answers after each send
- `--no-recv-fuzz`, `-nrf`: do not wait for answers after sending a fuzzed request
- `--check-recv`, `-cr`: check that data has been received after each sent request

### Crash options

- `--threshold-request`: set the number of allowed crashes in a request before skipping it (default: `9999`)
- `--threshold-element`: set the number of allowed crashes in a field before skipping it (default: `9999`)

Fuzzing an OPCUA server
-----------------------

Fuzzing with FuzzySully can specifically target :

- basic OPCUA messages related to secure channel creation, data read or write, OPCUA session, etc ;
- a client with a reverse connection ;
- specific messages targeting a GDS server using a certificate manager in **pull** mode.

### Fuzzing basic OPCUA services (`server` mode)

Basic OPCUA messages are sent over a connection that uses either the OPCUA security policy `None`,
(without any encryption nor authentication) or the `Basic256Sha256` with authentication. The target must be configured to accept the chosen security policy for the fuzzing process to succeed.

To start fuzzing a server with `None` security policy listening on port `4841` with a timeout of `2s` for sending and receiving data :

``` commandline
$ fuzzysully -st 2 -rt 2 server localhost 4841 "path"
Fuzzing paused! Welcome to the Fuzzowski Shell
[1 of XXXX] ➜ localhost:4841 $ 
```

The fuzzer is stopped by default on start, and fuzzing is started by typing `continue` or `c`:

``` commandline
Fuzzing paused! Welcome to the Fuzzowski Shell
[1 of XXXX] ➜ localhost:4841 $ c
[2024-04-05 09:19:48,073] Test Case: 1: [hello]->OpenSecureChannel->CloseSecureChannel.Protocol version.1 
[2024-04-05 09:19:48,087]     Info: Type: DWord. Default value: b'\x00\x00\x00\x00'. Case 1 of 1232705 overall.
[2024-04-05 09:19:48,096]     Info: Opening target connection (localhost:4841)...
[2024-04-05 09:19:48,101]     Info: Connection opened.
[2024-04-05 09:19:48,105]   Test Step: Fuzzing node hello
```

If you want to fuzz the server in `Sign` mode (*i.e.*, with `Basic256Sha256` security policy), you have to specify in addition : 
- the policy ;
- the path to the client certificate ;
- the path to the private key associate to this certificate ;
- the application Uri in the client certificate (e.g the certificate that fuzzysully will use.).

then you could use the following command :

```commandline
$ fuzzysully server localhost 4841 "/test" --policy Basic256Sha256 --client-cert <PEM/DER file path> --private-key <PEM file path> --private-key-password <password> --app-uri <uri>
Fuzzing paused! Welcome to the Fuzzowski Shell
[1 of 66567] ➜ localhost:4841 $
```

### Fuzzing GDS certificate manager (`gds` mode)
Fuzzing a GDS is quite similar to a classical server in `Sign` mode except that the encryption is required. Usually, application URI (e.g in client certificate) and GDS authentication (e.g user/password) should be specified in the CLI to match GDS specific configuration.

```commandline
$ fuzzysully gds localhost 4841 "" --policy Basic256Sha256 --client-cert <PEM/DER file path> --private-key <PEM file path> --private-key-password <password> --encrypt --app-uri <uri> --username <username> --password <user password>
Fuzzing paused! Welcome to the Fuzzowski Shell
[1 of 66567] ➜ localhost:4841 $
```

Fuzzing an OPCUA client (`reverse` mode)
-----------------------

FuzzySully is also capable of fuzzing an OPCUA client by initiating a reverse connection to a compatible client and send specific requests.

To fuzz a client with a *reverseEndpoint* configured to listen on `localhost`
port `4845`, you could use the following command :

``` commandline
$ fuzzysully reverse localhost 4845 "path" 
Fuzzing paused! Welcome to the Fuzzowski Shell
[1466 of XXXX] ➜ localhost:4845 $ c
[2024-04-05 09:25:05,486] Test Case: 1466: [ReverseHello]->ReverseHelloError.endpoint_uri.1466 
[2024-04-05 09:25:05,493]     Info: Type: String. Default value: b'opc.tcp://localhost:None'. Case 1466 of XXXX overall.
[2024-04-05 09:25:05,496]     Info: Opening target connection (localhost:4845)...
[2024-04-05 09:25:05,499]     Info: Connection opened.
[2024-04-05 09:25:05,502]   Test Step: Fuzzing node ReverseHello
[2024-04-05 09:25:05,507]   Test Step: Callback function
[2024-04-05 09:25:05,509]     Transmitting 12036 bytes: [12036 bytes]
[2024-04-05 09:25:05,512]     Info: 12036 bytes sent
[2024-04-05 09:25:05,515]     Info: Receiving...
[2024-04-05 09:25:06,518]     Received: 
[2024-04-05 09:25:06,526]   Test Step: Transmit node ReverseHelloError
[2024-04-05 09:25:06,529]   Test Step: Callback function
[2024-04-05 09:25:06,533]     Info: Test case aborted due to transmission error: 
[2024-04-05 09:25:06,537]   Test Step: Calling Monitor OPCUAMonReverse
```

The application URI value required in the `ReverseHello` message can be set
using the `--app-uri` option. By default, it is set to `urn:S2OPC:localhost`.


Known limitations
---

###  Stack variations and fuzzer compatibility
It is possible that OPC UA stacks have differences in implementations. Some may not be handled correctly by the fuzzer.

### The `goto` function performance and responsiveness

The `goto` function, when used to jump across thousands of test cases, may appear unresponsive but does not actually crash. For example, executing such a command might take approximately 15 seconds to load.
``` commandline
[1 of 61643] -> localhost:4840 $ goto 30000
[30000 of 61643] -> localhost:4840 $
```

### Suboptimal fuzzing path and `goto` workaround

The current implementation of the fuzzer does not optimize the fuzzing path. Consequently, some tests may be unnecessarily repeated. For instance, the command below will initiate the fuzzer with the fuzzing path [Hello]->OpenSecureChannel->CloseSecureChannel.
``` commandline
fuzzysully server localhost 4840 "" -f secure_channel
```
As a consequence, the first 2655 test cases (from 0 to 2655) are mutations of the Hello message. These are unnecessary if your intention is to fuzz only the OpenSecureChannel message.
To circumvent this limitation, you can utilize the `goto` function to jump directly to the OpenSecureChannel test cases.
``` commandline
[1 of 11734] -> localhost:4840 $ goto 2656
[2656 of 11734] -> localhost:4840 $
Fuzzing Path : hello->[OpenSecureChannel]->CloseSecureChannel
```


Acknowledgments
---

This project was funded by [`Agence Nationale de la Sécurité des Systèmes d'Information`](https://cyber.gouv.fr/).


Code Structure and Authorship
---

Fuzzysully ships three tools in its package:
- An enhanced version of [`opcua-asyncio`](https://github.com/FreeOpcUa/opcua-asyncio/tree/master) which supports encryption. This OPCUA server/client library has been created by Olivier Roulet-Dubonnet and is distributed under LGPL-3.0 license.
- A slightly modified version of the [`fuzzowski`](https://github.com/nccgroup/fuzzowski) fuzzer. Originally developed by NCC Group, this Network Protocol Fuzzer is distributed under the GPL-2.0 license.
- `fuzzysully` itself which has been developed by [Quarkslab](https://www.quarkslab.com).
  - The sub-parts that handle the fuzzing of the `Read`, `Browse`, `BrowseNext`, `CreateSubscription`, `Add Nodes` and `HistoryRead` services are based on the [fuzzing scripts](https://github.com/claroty/opcua_network_fuzzer/) written by Claroty for the Boofuzz fuzzer.
  - The sub-parts that handle the fuzzing of the `FindServers`, `FindServersOnNetwork`, `GetEndpoints`, `Hello`, `SecureChannel`, `RegisterServer2`, `CreateSession` and `ActivateSession` services are based on the [fuzzing scripts](https://github.com/fkie-cad/blackbox-opcua-fuzzing/) written by the Fraunhofer FKIE (financed by the German Federal Office for Information Security (BSI)) for the Boofuzz fuzzer.

-  Installing `fuzzysully` also installs `opcua-asyncio` and `fuzzowski` CLI tools.

Licence
---
See [LICENCE.md](LICENCE.md)


     This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; version 2 of the License.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program; if not, see <https://www.gnu.org/licenses/>.