// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

// SMTPTLS is the required transport security. There is no plaintext mode:
// credentials and messages never travel over an unencrypted channel.
type SMTPTLS string

const (
	// SMTPImplicitTLS connects with TLS from the first byte (submissions, 465).
	SMTPImplicitTLS SMTPTLS = "implicit"
	// SMTPStartTLS upgrades with STARTTLS before anything else (587) and
	// refuses to continue when the server does not offer it.
	SMTPStartTLS SMTPTLS = "starttls"
)

// SMTPConfig configures the SMTP submission sender. The recipient is the
// destination's address and the password is its sealed secret.
type SMTPConfig struct {
	Common
	Host string
	Port int
	TLS  SMTPTLS
	// Username is the AUTH PLAIN identity. RequireAuth makes a missing
	// credential a terminal failure instead of an unauthenticated submission.
	Username    string
	RequireAuth bool
	// From is the envelope and header sender.
	From string
	// RootCAs / ServerName verify the relay's certificate (system roots and
	// Host when nil/empty). Verification can not be disabled.
	RootCAs    *x509.CertPool
	ServerName string
	// LocalName is the EHLO name; empty means "soundpost.invalid".
	LocalName string
}

type smtpSender struct {
	cfg     SMTPConfig
	origin  string
	secrets SecretReader
}

const maxSMTPReadBytes = 256 << 10

// NewSMTP returns the SMTP submission sender.
func NewSMTP(config SMTPConfig, secrets SecretReader) (notify.Sender, error) {
	origin, err := config.prepared()
	if err != nil {
		return nil, err
	}
	if secrets == nil || config.Host == "" || config.Port < 1 || config.Port > 65535 {
		return nil, errors.New("providers: smtp needs host, port and secrets")
	}
	if config.TLS != SMTPImplicitTLS && config.TLS != SMTPStartTLS {
		return nil, errors.New("providers: smtp tls must be implicit or starttls")
	}
	if !cleanAddress(config.From) {
		return nil, errors.New("providers: invalid sender address")
	}
	if config.RequireAuth && config.Username == "" {
		return nil, errors.New("providers: smtp auth requires a username")
	}
	if strings.ContainsAny(config.Username, "\r\n\x00") || strings.ContainsAny(config.LocalName, "\r\n\x00 ") {
		return nil, errors.New("providers: invalid smtp identity")
	}
	if e := config.Egress.checkHost(model.ID{}, config.Host); e != nil && !errors.Is(e, errHostNotAllowed) {
		return nil, errors.New("providers: smtp host address is blocked by egress policy")
	}
	return &smtpSender{cfg: config, origin: origin, secrets: secrets}, nil
}

func cleanAddress(s string) bool {
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return false
	}
	for i := range len(s) {
		if s[i] <= 0x20 || s[i] >= 0x7f || s[i] == '<' || s[i] == '>' || s[i] == ',' || s[i] == ';' {
			return false
		}
	}
	return true
}

var queuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)queued as ([A-Za-z0-9._-]{1,64})`),
	regexp.MustCompile(`(?i)\bid[= ]([A-Za-z0-9._-]{1,64})`),
}

func queueID(reply string) string {
	for _, p := range queuePatterns {
		if m := p.FindStringSubmatch(reply); m != nil {
			return m[1]
		}
	}
	return ""
}

type limitConn struct {
	net.Conn
	left int
}

func (c *limitConn) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > c.left {
		p = p[:c.left]
	}
	n, err := c.Conn.Read(p)
	c.left -= n
	return n, err
}

// smtpSession tracks the protocol position that decides the outcome class.
type smtpSession struct {
	conn net.Conn
	tp   *textproto.Conn
	tls  bool
	// dataEnd is set just before the terminating "." is written: from then on a
	// failure may be a message the server already accepted.
	dataEnd bool
}

func (s *smtpSession) reset(c net.Conn) {
	s.conn = c
	s.tp = textproto.NewConn(&limitConn{Conn: c, left: maxSMTPReadBytes})
}

func (s *smtpSession) cmd(format string, args ...any) (int, string, error) {
	if err := s.tp.PrintfLine(format, args...); err != nil {
		return 0, "", err
	}
	return s.reply()
}

func (s *smtpSession) reply() (int, string, error) {
	code, msg, err := s.tp.ReadResponse(0)
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code, te.Msg, nil
	}
	return code, msg, err
}

// replyOutcome maps an unexpected SMTP reply before the message is committed.
func replyOutcome(code int) notify.Outcome {
	switch {
	case code >= 400 && code < 500:
		return retry("smtp_"+strconv.Itoa(code), 0)
	case code >= 500 && code < 600:
		return terminal("smtp_" + strconv.Itoa(code))
	}
	return retry("smtp_protocol", 0)
}

func (c SMTPConfig) tlsConfig() *tls.Config {
	name := c.ServerName
	if name == "" {
		name = c.Host
	}
	return &tls.Config{ServerName: name, RootCAs: c.RootCAs, MinVersion: tls.VersionTLS12}
}

func (s *smtpSender) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	dest, password, bad := resolve(ctx, s.cfg.Common, s.secrets, scope, d, notify.ChannelSMTP, s.cfg.RequireAuth)
	if bad != nil {
		return *bad, nil
	}
	defer zero(password)
	if s.cfg.Username != "" && len(password) == 0 {
		return terminal(codeSecretMissing), nil
	}
	if e := s.cfg.Egress.checkHost(scope.OrgID(), s.cfg.Host); e != nil {
		if errors.Is(e, errHostNotAllowed) {
			return terminal(codeHostNotAllowed), nil
		}
		return terminal(codeEgressBlocked), nil
	}
	msg := s.message(d, dest.Target)

	timeout := s.cfg.timeout()
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := s.cfg.Egress.dialContext(timeout)(dctx, "tcp", net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port)))
	if err != nil {
		if errors.Is(err, errEgressBlocked) {
			return terminal(codeEgressBlocked), nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return retry(codeConnectTimeout, 0), nil
		}
		return retry(codeConnectFailed, 0), nil
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(deadline) {
		deadline = cd
	}
	_ = conn.SetDeadline(deadline)

	sess := &smtpSession{}
	sess.reset(conn)
	if s.cfg.TLS == SMTPImplicitTLS {
		tc := tls.Client(conn, s.cfg.tlsConfig())
		if err = tc.HandshakeContext(dctx); err != nil {
			return retry(codeTLSFailed, 0), nil
		}
		sess.reset(tc)
		sess.tls = true
	}
	out, err := s.session(sess, d, dest.Target, password, msg, dctx)
	if err != nil {
		if sess.dataEnd {
			// The terminating line may have been delivered: possible acceptance.
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				return unknown(codeTimeout), nil
			}
			return unknown(codeTransport), nil
		}
		if isTimeout(err) {
			return retry(codeTimeout, 0), nil
		}
		return retry("smtp_io_error", 0), nil
	}
	return out, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (s *smtpSender) session(sess *smtpSession, d notify.Delivery, rcpt string, password, msg []byte, ctx context.Context) (notify.Outcome, error) {
	code, _, err := sess.reply()
	if err != nil {
		return notify.Outcome{}, err
	}
	if code != 220 {
		return replyOutcome(code), nil
	}
	name := s.cfg.LocalName
	if name == "" {
		name = "soundpost.invalid"
	}
	ehlo := func() (map[string]string, *notify.Outcome, error) {
		code, text, err := sess.cmd("EHLO %s", name)
		if err != nil {
			return nil, nil, err
		}
		if code != 250 {
			o := replyOutcome(code)
			return nil, &o, nil
		}
		ext := map[string]string{}
		for i, line := range strings.Split(text, "\n") {
			if i == 0 {
				continue
			}
			k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
			ext[strings.ToUpper(k)] = strings.ToUpper(v)
		}
		return ext, nil, nil
	}
	ext, o, err := ehlo()
	if err != nil || o != nil {
		if o != nil {
			return *o, nil
		}
		return notify.Outcome{}, err
	}
	if s.cfg.TLS == SMTPStartTLS && !sess.tls {
		if _, ok := ext["STARTTLS"]; !ok {
			// Never fall back to plaintext: nothing is sent, nothing is authenticated.
			return retry("starttls_unavailable", 0), nil
		}
		code, _, err = sess.cmd("STARTTLS")
		if err != nil {
			return notify.Outcome{}, err
		}
		if code != 220 {
			return retry("starttls_refused", 0), nil
		}
		tc := tls.Client(sess.conn, s.cfg.tlsConfig())
		if err = tc.HandshakeContext(ctx); err != nil {
			return retry(codeTLSFailed, 0), nil
		}
		sess.reset(tc)
		sess.tls = true
		if ext, o, err = ehlo(); err != nil || o != nil {
			if o != nil {
				return *o, nil
			}
			return notify.Outcome{}, err
		}
	}
	if !sess.tls {
		return retry("tls_required", 0), nil
	}
	if s.cfg.Username != "" {
		if !strings.Contains(" "+ext["AUTH"]+" ", " PLAIN ") {
			return terminal("auth_unsupported"), nil
		}
		cred := base64.StdEncoding.EncodeToString(append(append([]byte{0}, s.cfg.Username...), append([]byte{0}, password...)...))
		code, _, err = sess.cmd("AUTH PLAIN %s", cred)
		if err != nil {
			return notify.Outcome{}, err
		}
		if code != 235 {
			if code >= 400 && code < 500 {
				return retry("smtp_"+strconv.Itoa(code), 0), nil
			}
			return terminal("auth_failed"), nil
		}
	}
	if code, _, err = sess.cmd("MAIL FROM:<%s>", s.cfg.From); err != nil {
		return notify.Outcome{}, err
	}
	if code != 250 {
		return replyOutcome(code), nil
	}
	if code, _, err = sess.cmd("RCPT TO:<%s>", rcpt); err != nil {
		return notify.Outcome{}, err
	}
	if code != 250 && code != 251 {
		return replyOutcome(code), nil
	}
	if code, _, err = sess.cmd("DATA"); err != nil {
		return notify.Outcome{}, err
	}
	if code != 354 {
		return replyOutcome(code), nil
	}
	w := sess.tp.DotWriter()
	if _, err = w.Write(msg); err != nil {
		return notify.Outcome{}, err
	}
	sess.dataEnd = true
	if err = w.Close(); err != nil {
		return notify.Outcome{}, err
	}
	code, text, err := sess.reply()
	if err != nil {
		return notify.Outcome{}, err
	}
	switch {
	case code == 250:
		// Queued by the relay: an acceptance for delivery, not proof the
		// recipient read it. The queue ID is the relay's own evidence.
		id := queueID(text)
		if id == "" {
			id = "smtp-250:" + d.ID.String()
		}
		_, _, _ = sess.cmd("QUIT")
		return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: id}, nil
	case code >= 400 && code < 500:
		return retry("smtp_"+strconv.Itoa(code), 0), nil
	case code >= 500 && code < 600:
		return terminal("smtp_" + strconv.Itoa(code)), nil
	}
	return unknown("smtp_protocol"), nil
}

// message is the approved plain-text notification with a stable Message-ID, so
// a duplicate caused by an unknown attempt is recognizable by the recipient.
func (s *smtpSender) message(d notify.Delivery, rcpt string) []byte {
	subject, text := render(d, s.origin)
	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", s.cfg.From)
	h("To", rcpt)
	h("Subject", subject)
	h("Date", s.cfg.now().UTC().Format(time.RFC1123Z))
	h("Message-ID", fmt.Sprintf("<%s@soundpost.invalid>", d.ID.String()))
	h("X-Soundpost-Delivery-ID", d.ID.String())
	h("Auto-Submitted", "auto-generated")
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=us-ascii")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
	return []byte(b.String())
}
