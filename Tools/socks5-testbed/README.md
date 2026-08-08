# SOCKS5 testbed

A real SOCKS5 server for SplitLane's integration tests, in Docker.

```bash
Tools/socks5-testbed/up.sh
SPLITLANE_SOCKS5_INTEGRATION=1 swift test
Tools/socks5-testbed/down.sh
```

## What it provides

| Endpoint | Purpose |
|---|---|
| `127.0.0.1:11080` | SOCKS5, no authentication |
| `127.0.0.1:11081` | SOCKS5, username `splitlane`, password `lane-secret` |
| `origin.test:80` | nginx — reachable **only** through the proxies |

## Why the origin has no published ports

This is the point of the whole arrangement. `origin` sits on a Docker bridge network that the host
is not on, so nothing on the host can reach it directly:

```console
$ docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' splitlane-origin
172.18.0.2
$ curl --max-time 4 http://172.18.0.2/          # from the host
(fails — no route)
$ curl --socks5-hostname 127.0.0.1:11080 http://origin.test/
HTTP/1.1 200 OK
```

So when an integration test running on the host receives an HTTP response from `origin.test`, the
bytes can only have gone through the SOCKS5 proxy. A test against a host-reachable server would
pass whether or not the SOCKS5 layer did anything at all, which makes it worthless as evidence.

It also means `origin.test` resolves only inside the network, so `ATYP=DOMAIN` is exercised
properly: the *proxy* has to do the resolution, because the client cannot.

## Why not port 10808

10808 is SplitLane's real upstream default, and a developer working on this project very likely
has an actual proxy listening there. The testbed stays out of its way.

## Ports and credentials are fixture values

`splitlane` / `lane-secret` are test fixtures for a container with no network exposure beyond
loopback. They are not credentials for anything, and nothing outside this directory and
`SOCKS5IntegrationTests.swift` should reference them.

## Troubleshooting

```bash
docker compose -f Tools/socks5-testbed/docker-compose.yml ps
docker compose -f Tools/socks5-testbed/docker-compose.yml logs
docker compose -f Tools/socks5-testbed/docker-compose.yml logs socks5-noauth
```

If `up.sh` reports a port never became ready, something else is already bound to 11080 or 11081:

```bash
lsof -nP -iTCP:11080 -sTCP:LISTEN
```

The `serjs/go-socks5-proxy` image requires authentication by default and exits immediately if no
credentials are set, which is why the no-auth service passes `REQUIRE_AUTH=false`. A container
that exits on startup with no obvious error is almost always this.
