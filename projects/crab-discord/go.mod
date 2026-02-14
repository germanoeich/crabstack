module crabstack.local/projects/crab-discord

go 1.22

require (
	crabstack.local/projects/crab-sdk v0.0.0
	github.com/bwmarrin/discordgo v0.28.1
)

require (
	github.com/gorilla/websocket v1.5.3 // indirect
	golang.org/x/crypto v0.0.0-20210421170649-83a5a9bb288b // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

replace crabstack.local/projects/crab-sdk => ../crab-sdk
