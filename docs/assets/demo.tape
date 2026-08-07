# vhs tape — records a real terminal GIF of exalm running.
# Install vhs: https://github.com/charmbracelet/vhs  (go install github.com/charmbracelet/vhs@latest)
# Generate:   vhs docs/assets/demo.tape   →   docs/assets/demo.gif
#
# Prereqs in the shell that runs vhs:
#   - exalm on PATH (go build -o exalm ./cmd/exalm && export PATH=$PWD:$PATH)
#   - EXALM_LLM_PROVIDER=mock  (so the demo needs no API key and is deterministic)

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 17
Set Width 1200
Set Height 760
Set Padding 22
Set Theme "Catppuccin Mocha"

Hide
Type "export EXALM_LLM_PROVIDER=mock" Enter
Type "clear" Enter
Show

Type "# Privacy-first AI ops — analyze a syslog capture, secrets never leave the box" Sleep 1s Enter
Type "exalm syslog analyze --file examples/syslog/wsl-live-session.jsonl" Sleep 800ms Enter
Sleep 4s

Type "# Every finding carries severity, root cause, and a safe proposed fix" Sleep 1s Enter
Type "exalm syslog analyze --file examples/syslog/wsl-live-session.jsonl --output json | jq '.findings[] | {severity, title, fix: .remediation.kind}'" Sleep 800ms Enter
Sleep 4s
