// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

// DefaultTelegramAPI is the Telegram Bot API origin.
const DefaultTelegramAPI = "https://api.telegram.org"

// TelegramConfig configures the Telegram sender. The bot token is the
// destination's sealed secret and the chat is the destination's address; the
// API origin is operator configuration, never delivery data.
type TelegramConfig struct {
	Common
	// APIBase is the https Bot API origin; empty means DefaultTelegramAPI.
	APIBase string
}

type telegramSender struct {
	cfg     TelegramConfig
	origin  string
	api     string
	secrets SecretReader
	client  *http.Client
}

// NewTelegram returns the Telegram Bot API sender (HTTPS only).
func NewTelegram(config TelegramConfig, secrets SecretReader, client *http.Client) (notify.Sender, error) {
	origin, err := config.prepared()
	if err != nil {
		return nil, err
	}
	if secrets == nil {
		return nil, errors.New("providers: telegram needs a secret reader")
	}
	api := config.APIBase
	if api == "" {
		api = DefaultTelegramAPI
	}
	u, err := url.Parse(api)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("providers: telegram API base must be an https origin")
	}
	if e := config.Egress.checkHost(model.ID{}, u.Hostname()); e != nil && !errors.Is(e, errHostNotAllowed) {
		return nil, errors.New("providers: telegram API address is blocked by egress policy")
	}
	c, err := newHTTPClient(config.Common, client)
	if err != nil {
		return nil, err
	}
	return &telegramSender{cfg: config, origin: origin, api: "https://" + u.Host, secrets: secrets, client: c}, nil
}

type telegramRequest struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

type telegramResponse struct {
	OK        bool `json:"ok"`
	ErrorCode int  `json:"error_code"`
	Result    struct {
		MessageID int64 `json:"message_id"`
	} `json:"result"`
	Parameters struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (s *telegramSender) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	dest, token, bad := resolve(ctx, s.cfg.Common, s.secrets, scope, d, notify.ChannelTelegram, true)
	if bad != nil {
		return *bad, nil
	}
	defer zero(token)
	if e := s.cfg.Egress.checkHost(scope.OrgID(), hostOf(s.api)); e != nil {
		if errors.Is(e, errHostNotAllowed) {
			return terminal(codeHostNotAllowed), nil
		}
		return terminal(codeEgressBlocked), nil
	}
	_, text := render(d, s.origin)
	payload, err := json.Marshal(telegramRequest{ChatID: dest.Target, Text: text, DisableWebPagePreview: true})
	if err != nil {
		return terminal(codeBadResponse), nil
	}
	// The token is part of the URL path; it is never logged and no error text
	// from the transport is ever kept.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.api+"/bot"+string(token)+"/sendMessage", bytes.NewReader(payload))
	if err != nil {
		return terminal(codeDestInvalid), nil
	}
	req.Header.Set("Content-Type", "application/json")
	res := roundTrip(s.client, req)
	if o, failed := transportOutcome(res, ctx.Err()); failed {
		return o, nil
	}
	var tr telegramResponse
	parsed := json.Unmarshal(res.body, &tr) == nil
	after := time.Duration(0)
	if parsed && tr.Parameters.RetryAfter > 0 {
		after = time.Duration(tr.Parameters.RetryAfter) * time.Second
		if after > maxRetryAfter {
			after = maxRetryAfter
		}
	}
	if h := retryAfter(res.header, s.cfg.now()); h > after {
		after = h
	}
	switch st := res.status; {
	case st >= 200 && st < 300:
		if parsed && tr.OK && tr.Result.MessageID > 0 {
			// Accepted by the Bot API; not proof a human saw it.
			return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: strconv.FormatInt(tr.Result.MessageID, 10)}, nil
		}
		if parsed && !tr.OK && tr.ErrorCode == 429 {
			return retry(codeRateLimited, after), nil
		}
		// A 2xx we can not read as an acceptance may still have sent it.
		return unknown(codeBadResponse), nil
	case st == http.StatusTooManyRequests:
		return retry(codeRateLimited, after), nil
	case st == http.StatusRequestTimeout || st >= 500:
		return retry("http_"+strconv.Itoa(st), after), nil
	default:
		return terminal("http_" + strconv.Itoa(st)), nil
	}
}

func hostOf(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return strings.TrimPrefix(origin, "https://")
	}
	return u.Hostname()
}
