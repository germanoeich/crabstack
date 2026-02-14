module crabstack.local/projects/crab-cli

go 1.22

require (
	crabstack.local/projects/crab-sdk v0.0.0
	github.com/gdamore/tcell/v2 v2.7.1
	github.com/gorilla/websocket v1.5.3
	github.com/rivo/tview v0.0.0-20241227133733-17b7edb88c57
)

require (
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/term v0.17.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace crabstack.local/projects/crab-sdk => ../crab-sdk
