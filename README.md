# Deltatronix Agent

Run Deltatronix AI vision tasks on your own computer. The agent connects your
Deltatronix account to a local model server, processes assigned tasks, and sends
the results back to Deltatronix.

Use the desktop app for a window and system-tray controls, or the headless version
for a terminal or server. The agent initiates its connection to Deltatronix, so
you do not need to set up port forwarding.

## What you need

- **The agent itself**: download it from
  [Releases](https://github.com/Deltatronix/Deltatronix-agent/releases), or
  build it from source with **Git and Go 1.26 or newer**.
- **A local model server**, such as [Ollama](https://ollama.com/download) or
  [LM Studio](https://lmstudio.ai), with a compatible vision model installed.
- **A Deltatronix account and pairing code** to connect the agent and receive tasks.

You can build this repository on its own. Pairing and running Deltatronix tasks
require access to the Deltatronix service. The agent does not include a model
server or download models for you.

## Download a release

Each release has one file per platform:

| File | Platform |
| --- | --- |
| `dtx-agent-darwin-arm64` | macOS, Apple silicon, desktop app |
| `dtx-agent-darwin-amd64` | macOS, Intel, desktop app |
| `dtx-agent-windows-amd64.exe` | Windows x64, desktop app |
| `dtx-agent-linux-amd64` | Linux x64, desktop app |
| `dtx-agent-linux-amd64-headless` | Linux x64, headless (servers, containers) |
| `llm.txt` | The default settings template |

The desktop builds also run headless with `run --headless`. Rename the file to
`dtx-agent` (`dtx-agent.exe` on Windows) and make it executable on macOS and
Linux:

```sh
mv dtx-agent-darwin-arm64 dtx-agent
chmod +x dtx-agent
```

The binaries are not code-signed. macOS blocks a downloaded unsigned binary
with "cannot be opened because the developer cannot be verified"; after
checking the file came from this repository's release page, clear the
download flag once with `xattr -d com.apple.quarantine dtx-agent`. Windows
SmartScreen may ask you to confirm with **More info → Run anyway**.

## Build from source

Clone this repository, or fork it first and use your fork's URL:

```sh
git clone https://github.com/Deltatronix/Deltatronix-agent.git
cd Deltatronix-agent
```

Choose one of the following builds. Go downloads the required packages during
the first build.

### Desktop app

The desktop app uses Fyne and requires a C compiler and platform development
libraries. Follow the [Fyne setup guide](https://docs.fyne.io/started/) for your
operating system. On macOS, install the Xcode Command Line Tools; on Windows,
use a compatible C compiler as described in that guide.

On Ubuntu or Debian, install the desktop dependencies:

```sh
sudo apt-get update
sudo apt-get install -y build-essential libgtk-3-dev libayatana-appindicator3-dev libgl1-mesa-dev xorg-dev libxkbcommon-dev
```

Build on macOS or Linux:

```sh
CGO_ENABLED=1 go build -tags gui -o dtx-agent .
./dtx-agent
```

Build on Windows using PowerShell:

```powershell
$env:CGO_ENABLED = "1"
go build -tags gui -ldflags "-H=windowsgui" -o dtx-agent.exe .
.\dtx-agent.exe
```

### Headless agent

This build has no window or tray icon and does not require the desktop libraries:

```sh
go build -o dtx-agent .
```

On Windows, use `go build -o dtx-agent.exe .` and run commands with
`.\dtx-agent.exe` instead of `./dtx-agent`.

Pair the agent before starting it, as described below. Always use
`run --headless` with this build.

## Connect your agent

### 1. Start your local model server

Install and start Ollama or LM Studio. In LM Studio, load a vision model and
start its local server from the **Developer** tab.

The default connection is Ollama at `http://localhost:11434/v1`. For LM Studio,
open the agent's **Settings**, select **LM Studio**, save, and restart. Its
default URL is `http://localhost:1234/v1`.

For a headless setup, edit the per-user `llm.txt` file described under
[Configuration](#configuration). Running `./dtx-agent run --headless` once creates
that file, even if the agent has not been paired yet.

### 2. Pair with Deltatronix

In Deltatronix, open **Settings → Local agents → Add agent** and get a pairing
code. Enter it on the desktop app's **Status** page and select **Pair**.

From a terminal, replace `YOUR_PAIRING_CODE` with your code:

```sh
./dtx-agent pair YOUR_PAIRING_CODE
./dtx-agent run --headless
```

### 3. Check that the agent is ready

The **Status** page shows the Deltatronix connection and local model server
status. The agent checks for a compatible vision model and reports missing
models in its logs. Install a model requested by the agent; with Ollama, use
`ollama pull` followed by the model name shown in the log.

Keep the model server and agent running while you use local AI features in
Deltatronix. The agent retries automatically if a connection is interrupted.
Retries use jittered backoff from one to sixty seconds. Authentication rejection
(WebSocket 4401) and policy/rate-limit rejection (1008) retain that backoff even if
the WebSocket upgrade succeeded. Temporary backend failures can also reject
authentication, so the agent keeps retrying instead of deleting its pairing.
If the pairing was revoked, get a new code, pair again and restart the headless
agent; in the desktop app, use Disconnect and then Pair. Each ended connection
cancels and joins its jobs before the connect loop retries.

## Local Shape execution

The same paired agent can run bounded Shape regeneration and STEP/STL exports
without a model server. This first native runtime supports Docker Linux arm64
with cgroup v2 (including Docker Desktop on Apple Silicon). Install Docker and
pull the pinned base image once:

```sh
docker pull node@sha256:78bc820a7a6148e8c48731eca18dbb9b6b2c05ac4a52138479be565f2831682d
```

Pair and run the agent normally. It advertises `shape.native.v1` when the local
containment prerequisites pass. The server selects the runtime release; the agent
downloads it through the existing authenticated connection, verifies its pinned
Ed25519 signing key and archive/executable/WASM hashes, and runs its compiled
Deno executable. The base image supplies system libraries. Runtime downloads do
not require a GitHub token or local Deno installation.

Each job has a read-only filesystem, no network, an unprivileged user, 1 GiB
memory with no swap, one CPU and at most 64 processes. Inputs and outputs have
explicit size limits. The agent renews its server lease every second and kills
the container if the lease expires, pairing disconnects, or cancellation cannot
finish within 250 ms. Containers are removed after jobs; reconnecting removes
orphaned containers belonging to this pairing. Unsupported platforms refuse
native work while vision capabilities continue independently.

Regeneration returns a verification receipt for the saved document version.
Exports upload real project files through the server's normal storage path.

Assembly verification uses each saved source version and configuration, even
when newer versions exist. Missing or inaccessible pinned sources require an
explicit fix; verification never advances sources automatically or saves derived
poses into the assembly. Part regeneration and STEP/STL exports remain available.

## Everyday use

- **Open the desktop app:** run `./dtx-agent`.
- **Find a running app:** use its system-tray icon and select **Open**. A paired
  agent starts in the tray; closing its window keeps it running.
- **Stop the desktop app:** select **Quit** from the tray menu.
- **Run without a window:** use `./dtx-agent run --headless`; press Ctrl+C to stop
  an agent running in your terminal.
- **Disconnect your account:** select **Disconnect** on the desktop **Status**
  page, or revoke the agent from Deltatronix.
- **Start on login:** enable **Start automatically on login** in Settings.

The startup and PATH options are also available from a terminal:

| Action | Command |
| --- | --- |
| Start the desktop app on login | `./dtx-agent autostart enable` |
| Start the headless agent on login | `./dtx-agent autostart enable --headless` |
| Turn off startup on login | `./dtx-agent autostart disable` |
| Add the agent to PATH | `./dtx-agent path add` |
| Remove it from PATH | `./dtx-agent path remove` |

Choose the startup command that matches your build. On Linux, add
`--mode systemd` to `autostart enable --headless` to use a user systemd service.
After adding the agent to PATH, you can use `dtx-agent` without the `./` prefix.

## Configuration

The agent stores its settings in your user configuration folder. Set
`DTX_AGENT_CONFIG_DIR` to an absolute directory to use a separate pairing/profile
without changing the desktop pairing. For clipboard-based pairing, pipe the
code to `dtx-agent pair --code-stdin` so it does not appear in process arguments.

Default locations:

| Operating system | Default folder |
| --- | --- |
| macOS | `~/Library/Application Support/dtx-agent/` |
| Linux | `~/.config/dtx-agent/` (or `$XDG_CONFIG_HOME/dtx-agent/` if set) |
| Windows | `%AppData%\dtx-agent\` |

- **`llm.txt`** contains the model server URL and logging settings. The agent
  creates it on first run. Edit it through **Settings**, or directly for a
  headless setup, then restart the agent.
- **`config.json`** stores your pairing credentials. Keep it private and out of
  your fork or commits.
- **`dtx-agent.log`** contains runtime logs by default. Desktop users can also
  view logs in **Settings**.

Example `llm.txt`:

```ini
backend_url=http://localhost:11434/v1
log=on
log_dir=
log_max_size_mb=10
log_max_files=3
```

Leave `log_dir` empty to keep logs in the configuration folder. The
[`llm.txt`](llm.txt) in this repository is the default template; edit your
per-user copy to change the running agent's settings.

## Local tool chat: companion-side support

Tool chat is opt-in. In your per-user `llm.txt`, set `chat_model` to the **exact**
installed ID from the model server's `/v1/models` response, and set
`chat_context_tokens` to a positive cap you have verified for that model. For
example, an installed Ollama `gemma4:latest` can be selected with:

```ini
backend_url=http://127.0.0.1:11434/v1
chat_model=gemma4:latest
chat_context_tokens=131072
```

Restart after editing. The GUI preserves these two keys when saving settings;
edit them in the file. Empty model and zero cap disable chat. Missing, invalid,
or uninstalled selections never pick another model. Chat accepts only loopback
HTTP(S) `/v1` servers, disables HTTP proxies and rejects redirects. Existing
vision model matching and substitution stay unchanged.

The companion advertises `llm.chat` only after listing the selected installed
model and receiving one valid scripted tool call from it. That probe runs real
inference, so it runs once per connection and again only after the selected
model leaves and returns to the `/models` listing; the 60-second recheck only
lists models. The probe allows 1,024 output tokens so a thinking model (for example
`qwen3:8b`) can reason before its call. A failed probe leaves chat unavailable
until the next connection and logs why. A chat job that arrives before this
connection's probe has answered (the backend restores `llm.chat` on reconnect)
fails with `CHAT_PROBE_PENDING`, so the editor asks the user to try again
instead of reporting a lost model.

Every capabilities frame names the companion's `version`. With `llm.chat`, it
also names the model, its context cap and the request bytes the model's
tokenizer packs into one token, measured on the probe (1 to 3; 1 when the
server reports no usage):

```json
{"type":"capabilities","version":"0.1.4","capabilities":["llm.chat"],"chat":{"model":"gemma4:latest","contextTokens":131072,"bytesPerToken":3}}
```

On Ollama (detected by `GET /api/version` next to `/v1`), chat runs through the
native `/api/chat` endpoint with `options.num_ctx` set to `chat_context_tokens`,
because Ollama's `/v1` endpoint takes no context size and would run the model at
the server default, silently cutting long prompts. Other servers (LM Studio and
the rest) use `/v1/chat/completions`; set the model's context in the server to
at least `chat_context_tokens`.

The only ingress is the existing outbound bearer-paired `/compute/ws`
connection. No inbound bridge or local tool/shell execution exists. The model
emits tool calls for the browser to validate and execute.

The assignment contract is `type: "job.assign"`, a separate
`jobType: "LLM_CHAT_TOOLS"`, a unique `jobId`, RFC 3339 `expiresAt` in the next
five minutes, and `payload: { model, messages, tools, maxTokens }`. `model` must
equal the advertised model. Unknown fields, duplicate JSON members and invalid
UTF-8 are rejected. Text messages use `system`, `user`, `assistant` or `tool`
roles; historical tool calls/results must form complete pairs. Images use the
existing vision path. `responseSchema`, streaming, and additional provider
options are unsupported in this chat contract.

Tools use OpenAI function descriptors with `strict: true` and an object
`parameters` schema, which is passed to the model unchanged. The browser runtime
owns argument validation. The companion checks only that each tool call names an
advertised tool and carries a JSON object of at most 8 KiB; arguments of the
wrong type reach the browser, which returns a recoverable refusal to the model.
A call that fails the companion's check does not fail the job: the model sees
why as that call's tool error. A round with valid calls returns only those, and
the refused calls rejoin the round, with their errors, when a later job of the
turn replays it (kept in memory for one hour). A round with no valid call is
answered with its errors and asked again, at most twice, before the job fails
with `CHAT_INVALID_TOOL_CALL`.
A completion that stops at `maxTokens` (`finish_reason: "length"`) fails with
`CHAT_TRUNCATED`. A job whose model does not finish within its time limit fails
with `CHAT_LOCAL_TIMEOUT`; an assignment that arrives already expired fails with
`CHAT_EXPIRED`, the code the backend also uses for a job never picked up.

| Limit | Bound |
| --- | --- |
| Assignment / local request / upstream response | 64 KiB each |
| Normalized completion | 60 KiB, leaving room for the result envelope |
| Messages / tools / calls per assistant message | 64 / 20 / 8 |
| Message content / tool arguments | 16 KiB / 8 KiB |
| Tool description | 8 KiB |
| Installed model listing | 64 KiB / 256 IDs / 200 bytes per ID |
| Explicit context / output cap | 1 to 1,048,576 / 1 to 8,192 tokens |
| Probe / inference timeout | 180 seconds each; earlier expiry or cancellation wins |

Context admission counts serialized input bytes at the probe's measured bytes
per token, plus 1,024 tokens of framing allowance and the requested output cap. A request that
does not fit is refused rather than truncated. Results use the existing
`job.result` envelope with `ok`, and either a stable error code or normalized
OpenAI `model`, single `choices` entry and `usage`. Extra upstream metadata and
private reasoning fields are omitted. Raw messages, arguments and tokens are
not logged.

One shared slot handles vision and chat jobs. Cancellation, expiry, unpairing
and connection loss abort in-flight chat HTTP requests. Accepted chat job IDs
remain blocked for one hour across reconnects under the same API URL, agent ID
and pairing token. The process retains at most 4,096 tombstones and refuses new
jobs when full, rather than evicting unexpired protection. This is process-local
replay protection; it does not survive agent restart. Backend leases, ownership,
project scope and durable duplicate-result handling still belong to the backend.

The backend `LLM_CHAT_TOOLS` job type and capability dispatch are a separate
dependency.
This companion support and its synthetic paired-backend tests do **not** prove
real platform dispatch or an editor inspect/edit/check/save/reopen workflow.
Geometry still requires the open editor.

### Opt-in live local-model check

The live test uses a temporary test profile and the real selected local model,
with a synthetic authenticated backend. It makes no hosted calls, downloads no
models and leaves your normal configuration untouched. It is skipped unless all
three variables are supplied. On the development Mac, run through the shared
heavy-check queue (allow cold-start time):

```sh
export PATH=/Users/diandeskov/.nvm/versions/node/v22.23.2/bin:$PATH
export GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0
DTX_LIVE_CHAT_URL=http://127.0.0.1:11434/v1 \
DTX_LIVE_CHAT_MODEL=gemma4:latest \
DTX_LIVE_CHAT_CONTEXT_TOKENS=131072 \
/Users/diandeskov/Documents/GitHub/Deltatronix/dtx-heavy.sh local-chat-live -- \
  go test -count=1 -v -timeout=6m -run '^TestLivePairedLocalChatTools$' .
```

This checks production installation/probing and a real model tool call through
the job handler. It sends the returned assistant call and a synthetic tool result
with that exact call ID back to the same selected model, checks the follow-up
completion acknowledges the synthetic receipt, then cancels a third accepted job.
Deterministic
HTTP fixtures separately check aborting an in-flight model request. A skipped
live test is not a successful live-model proof.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| “This build has no GUI” | Run with `run --headless`, or rebuild with `-tags gui` for the desktop app. |
| “Not paired” | Pair from the desktop Status page or run `./dtx-agent pair YOUR_PAIRING_CODE`. |
| Model server is unreachable | Start your model server and check `backend_url` in Settings or `llm.txt`. |
| Connected, but no vision model is available | Check the logs for the requested model and install or load it in your model server. |
| The desktop window is missing | Check the system tray and select **Open**. |
| Desktop build fails on graphics or C libraries | Check the Fyne prerequisites and the desktop dependencies listed above. |

## Development

Run the tests with:

```sh
go test ./...
```

The [`Dockerfile`](Dockerfile) builds a headless container. Mount your paired
`config.json` and your `llm.txt` in `/home/nonroot/.config/dtx-agent/`. Set
`backend_url` to a model server address the container can reach; inside a
container, `localhost` refers to the container itself.

### Releasing

Releases are built and published by
[`.github/workflows/release.yml`](.github/workflows/release.yml) when a `v*`
tag is pushed. Maintainers with push access to `Deltatronix/Deltatronix-agent`:

1. Set `version` in [`version.go`](version.go) to the new version (for
   example `0.2.0`), merge that change to `master`, and pull it.
2. Run `go test ./...` on `master`.
3. Tag the merged commit with the same version and push the tag:

   ```sh
   git tag -a v0.2.0 -m "dtx-agent 0.2.0"
   git push origin v0.2.0
   ```

4. The workflow refuses a tag that differs from `version.go`, runs the tests,
   builds the six files listed under [Download a release](#download-a-release)
   on native runners, and publishes them as the GitHub release for the tag.
   Watch it with `gh run watch` and check the release page lists every file.
5. On a Mac, download the `darwin-arm64` file and pair and run it once to
   confirm it connects.

No signing keys or secrets are needed: the workflow publishes with the
repository's own `GITHUB_TOKEN`. A failed run publishes nothing; fix the cause
on `master`, delete the tag (`git push origin :v0.2.0`, `git tag -d v0.2.0`),
and tag again.

Issues and pull requests are disabled for this repository. Developers can fork,
clone, and build the agent, and keep their changes in their own forks.
