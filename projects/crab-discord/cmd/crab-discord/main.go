package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"

	"crabstack.local/projects/crab-discord/internal/chanmap"
	"crabstack.local/projects/crab-discord/internal/config"
	"crabstack.local/projects/crab-discord/internal/consumer"
	"crabstack.local/projects/crab-discord/internal/listener"
)

func main() {
	logger := log.New(os.Stdout, "crab-discord ", log.Ldate|log.Ltime|log.Lmicroseconds|log.LUTC)

	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		logger.Fatalf("invalid config: %v", err)
	}

	channelRegistry := chanmap.NewChannelRegistry()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	l := listener.NewListener(cfg, logger, httpClient, channelRegistry)

	discordSender, err := newDiscordSender(cfg.DiscordBotToken)
	if err != nil {
		logger.Fatalf("failed to create discord sender: %v", err)
	}
	c := consumer.NewConsumer(cfg, discordSender, logger)
	c.SetChannelRegistry(channelRegistry)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := l.Start(ctx); err != nil {
		logger.Fatalf("failed to start listener: %v", err)
	}
	if err := c.Start(ctx); err != nil {
		_ = l.Stop()
		logger.Fatalf("failed to start consumer: %v", err)
	}

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	done := make(chan error, 2)
	go func() {
		done <- l.Stop()
	}()
	go func() {
		done <- c.Stop(shutdownCtx)
	}()

	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				logger.Printf("shutdown error: %v", err)
			}
		case <-shutdownCtx.Done():
			logger.Printf("shutdown timed out")
			return
		}
	}
}

type discordSender struct {
	session *discordgo.Session
}

func newDiscordSender(token string) (*discordSender, error) {
	session, err := discordgo.New(normalizeBotToken(token))
	if err != nil {
		return nil, fmt.Errorf("create discord session: %w", err)
	}
	return &discordSender{session: session}, nil
}

func (s *discordSender) SendMessage(channelID string, content string) error {
	channelID = strings.TrimSpace(channelID)
	content = strings.TrimSpace(content)
	if channelID == "" {
		return fmt.Errorf("channel id is required")
	}
	if content == "" {
		return nil
	}
	_, err := s.session.ChannelMessageSend(channelID, content)
	return err
}

func normalizeBotToken(token string) string {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "bot ") {
		return token
	}
	return "Bot " + token
}
