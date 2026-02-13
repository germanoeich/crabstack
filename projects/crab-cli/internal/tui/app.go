package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"crabstack.local/lib/types"
	"crabstack.local/projects/crab-cli/internal/client"
)

func Run(ctx context.Context, cfg client.Config) error {
	cli, err := client.New(cfg)
	if err != nil {
		return err
	}
	defer cli.Close()

	app := tview.NewApplication()

	statusView := tview.NewTextView().
		SetDynamicColors(true).
		SetText("[yellow]status: disconnected")
	statusView.SetBorder(true).SetTitle("Connection")

	eventsView := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true).
		SetScrollable(true)
	eventsView.SetBorder(true).SetTitle("Gateway Events")

	helpView := tview.NewTextView().
		SetDynamicColors(true).
		SetText("Enter sends a channel.message.received event. Type /quit to exit.")
	helpView.SetBorder(true).SetTitle("Help")

	input := tview.NewInputField().
		SetLabel("Send text> ").
		SetFieldWidth(0)
	input.SetBorder(true).SetTitle("Compose")

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(statusView, 3, 0, false).
		AddItem(eventsView, 0, 1, false).
		AddItem(helpView, 3, 0, false).
		AddItem(input, 3, 0, true)

	appendLine := func(line string) {
		_, _ = fmt.Fprintf(eventsView, "%s\n", line)
		eventsView.ScrollToEnd()
	}
	setStatus := func(line string) {
		statusView.SetText(line)
	}

	input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		text := strings.TrimSpace(input.GetText())
		if text == "" {
			return
		}
		input.SetText("")

		if text == "/quit" {
			app.Stop()
			return
		}

		go func(message string) {
			sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := cli.SendTextMessage(sendCtx, message); err != nil {
				app.QueueUpdateDraw(func() {
					appendLine(fmt.Sprintf("[red]%s send failed: %v", timestamp(), err))
				})
				return
			}
			app.QueueUpdateDraw(func() {
				appendLine(fmt.Sprintf("[gray]%s sent: %s", timestamp(), message))
			})
		}(text)
	})

	go func() {
		app.QueueUpdateDraw(func() {
			setStatus("[yellow]status: pairing")
		})

		if err := cli.Connect(ctx); err != nil {
			app.QueueUpdateDraw(func() {
				setStatus(fmt.Sprintf("[red]status: pairing failed (%v)", err))
				appendLine(fmt.Sprintf("[red]%s pairing failed: %v", timestamp(), err))
			})
			return
		}

		app.QueueUpdateDraw(func() {
			setStatus("[green]status: paired")
			appendLine(fmt.Sprintf("[green]%s pairing complete", timestamp()))
		})

		for {
			select {
			case <-ctx.Done():
				app.QueueUpdateDraw(func() {
					appendLine(fmt.Sprintf("[yellow]%s context closed: %v", timestamp(), ctx.Err()))
				})
				return
			case <-cli.Done():
				app.QueueUpdateDraw(func() {
					setStatus("[yellow]status: disconnected")
				})
				return
			case err := <-cli.Errors():
				app.QueueUpdateDraw(func() {
					appendLine(fmt.Sprintf("[red]%s transport error: %v", timestamp(), err))
				})
			case event := <-cli.Events():
				formatted := formatEvent(event)
				app.QueueUpdateDraw(func() {
					appendLine(formatted)
				})
			}
		}
	}()

	if err := app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		return err
	}
	return nil
}

func formatEvent(event types.EventEnvelope) string {
	payload := string(event.Payload)
	if len(payload) > 300 {
		payload = payload[:300] + "..."
	}
	return fmt.Sprintf("[white]%s event=%s id=%s source=%s/%s payload=%s", timestamp(), event.EventType, event.EventID, event.Source.ComponentType, event.Source.ComponentID, payload)
}

func timestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
