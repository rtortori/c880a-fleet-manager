# C880A Redfish simulator

Run a synthetic C880A BMC over HTTPS for collection and onboarding tests. The simulator works without installing the manager. It exposes a fixed, public lab login: **admin/admin**. Use it only on loopback or an isolated test network.

## Setup

From the repository checkout, create a Python environment and install the certificate library:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install 'cryptography>=44'
```

## Start one simulator

```sh
.venv/bin/python scripts/redfish_simulator.py --ip 127.0.0.1 --port 9999
```

The process prints its HTTPS URL, PID, and generated public certificate path. The certificate and private key live in a private temporary directory and are deleted when the process stops. Copy the public certificate while the process runs if a manager or client needs to trust it. Use Ctrl-C to stop the foreground process, then confirm the URL no longer responds.

To use a specific private lab interface, add `--allow-nonloopback` and an IP assigned to this host. Link-local, multicast, and unspecified addresses are rejected. The script does not change network interfaces or firewall rules. The client must be able to reach the selected IP and port.

## Run several on one IP

Each invocation owns one listener. Use a different port for each process:

```sh
.venv/bin/python scripts/redfish_simulator.py --ip 127.0.0.1 --port 9999
.venv/bin/python scripts/redfish_simulator.py --ip 127.0.0.1 --port 10000
```

To run one in the background and capture the specific process ID:

```sh
.venv/bin/python scripts/redfish_simulator.py --ip 127.0.0.1 --port 9999 >simulator-9999.log 2>&1 &
simulator_pid=$!
printf 'Simulator PID: %s\n' "$simulator_pid"
```

Use `ps -p "$simulator_pid" -o pid=,command=` to identify it. Stop only that process with `kill "$simulator_pid"`, then use `wait "$simulator_pid"` in the same shell and confirm its port is closed. Do not use a broad process-name kill when several simulators are running. Remove the log file when finished.

## Connect a manager

In **Configuration → Security**, install the simulator's public certificate as a custom BMC CA bundle. For several simulators with generated certificates, concatenate their public certificates into one PEM bundle and install that bundle. Then use **Servers → Onboard server** with the simulator IP, its HTTPS port, and **admin/admin**. Leave the untrusted-certificate exception off. The manager defaults the BMC port to 443 for ordinary servers and treats IP and port together as the target identity, so two simulators on one IP can both be claimed.

The simulator serves `/redfish/v1` and the manager-used `Systems/DGX`, `Systems/HGX`, `Chassis/DGX`, and `Managers/BMC` resources. Their linked collections include processors, memory, storage, network interfaces and adapters, power supplies, thermal and power data, sensors, TelemetryService reports, and log services. Synthetic action/task responses support manager workflow tests. The packaged sensor profile contains the 336 sanitized identities observed on the supplied C880A: 137 temperatures, 64 fan speeds, 53 power readings, 24 voltages, 12 energy readings, one current reading, and 45 generic readings. Seventeen identities intentionally have no numeric reading, matching the saved observation. Values vary deterministically within plausible bounds for a given seed and tick; they are simulated values, not a replay of private device data.

`--scenario` can select a JSON profile, seed, tick interval, latency, and fault windows. Accepted top-level keys are `profiles`, `seed`, `tick_seconds`, `latency`, and `faults`; see the [simulator validation](src/c880a_manager/simulator.py) for the bounded fields. The Redfish simulator does not generate a vKVM video stream.

To provide your own lab certificate, use `--cert CERT.pem --key KEY.pem`. The certificate must cover the bound IP, and the key file must be owner-only. The process never switches to HTTP.
