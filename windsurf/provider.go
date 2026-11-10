// Package windsurf implements llm.Provider for Devin/Windsurf SWE-2 models via
// the Codeium Connect protocol (protobuf over HTTP POST). No .proto dependency;
// all encoding/decoding is hand-rolled from the reverse-engineered schema.
package windsurf

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

const (
	getChatMessagePath = "/exa.api_server_pb.ApiServerService/GetChatMessage"
	ideName            = "devin"
	ideVersion         = "3000.11.228"
	planName           = "Pro"

	// Protobuf source values for ChatMessagePrompt.source (field 2).
	sourceUser      = 1
	sourceAssistant = 2 // Codeium calls this "SYSTEM" internally
	sourceTool      = 4

	// Request type CASCADE (field 7).
	requestTypeCascade = 5

	// Stop reasons from GetChatMessageResponse.stop_reason (field 5).
	stopEndTurn  = 2
	stopMaxToks  = 3
	stopToolUse  = 10
)

// Config configures the Windsurf provider.
type Config struct {
	BaseURL    string
	APIKey     string // Devin session token
	Model      string
	HTTPClient *http.Client
}

type provider struct {
	cfg Config
}

// NewProvider creates a Windsurf llm.Provider.
func NewProvider(cfg Config) (llm.Provider, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://server.codeium.com"
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("windsurf: api key (devin session token) is required")
	}
	if cfg.Model == "" {
		cfg.Model = "swe-2-high"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	return &provider{cfg: cfg}, nil
}

// Stream implements llm.Provider. It sends a single protobuf request and parses
// the Connect response frames into normalized StreamEvents.
func (p *provider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		body, err := p.buildRequest(req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		httpReq, err := http.NewRequestWithContext(ctx, "POST", p.cfg.BaseURL+getChatMessagePath, bytes.NewReader(envelopeWrap(body)))
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		httpReq.Header.Set("Content-Type", "application/connect+proto")
		httpReq.Header.Set("Connect-Protocol-Version", "1")
		httpReq.Header.Set("windsurf-api-key", p.cfg.APIKey)

		resp, err := p.cfg.HTTPClient.Do(httpReq)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			yield(llm.StreamEvent{}, fmt.Errorf("windsurf: HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 500)))
			return
		}

		// Emit message_start
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}

		var (
			usage      llm.Usage
			stopReason string
			// Tool call accumulation: id → accumulated JSON fragments
			toolArgs = make(map[string]*strings.Builder)
			toolNames = make(map[string]string)
		)

		for {
			frame, ferr := readFrame(resp.Body)
			if ferr != nil {
				if ferr == io.EOF || ferr == io.ErrUnexpectedEOF {
					break
				}
				yield(llm.StreamEvent{}, ferr)
				return
			}
			if frame.IsTrailer {
				if terr := parseTrailerError(frame.Data); terr != nil {
					yield(llm.StreamEvent{}, terr)
					return
				}
				break
			}

			fields, perr := decodeFields(frame.Data)
			if perr != nil {
				yield(llm.StreamEvent{}, fmt.Errorf("windsurf: decode response frame: %w", perr))
				return
			}

			// delta_text (field 3)
			if text := fieldString(fields, 3); text != "" {
				if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: text}, nil) {
					return
				}
			}

			// delta_thinking (field 9)
			if thinking := fieldString(fields, 9); thinking != "" {
				if !yield(llm.StreamEvent{Type: llm.SEThinkingDelta, Text: thinking}, nil) {
					return
				}
			}

			// delta_signature (field 10)
			if sig := fieldString(fields, 10); sig != "" {
				if !yield(llm.StreamEvent{Type: llm.SEThinkingSignature, Text: sig}, nil) {
					return
				}
			}

			// tool_calls (field 6, repeated)
			for _, tcData := range fieldAllSubmsg(fields, 6) {
				tcFields, tcErr := decodeFields(tcData)
				if tcErr != nil {
					continue
				}
				toolID := fieldString(tcFields, 1)
				toolName := fieldString(tcFields, 2)
				argDelta := fieldString(tcFields, 3)

				if toolName != "" {
					toolNames[toolID] = toolName
				}
				if _, ok := toolArgs[toolID]; !ok {
					// New tool call
					name := toolName
					if name == "" {
						name = toolNames[toolID]
					}
					toolArgs[toolID] = &strings.Builder{}
					if !yield(llm.StreamEvent{
						Type:     llm.SEToolUseStart,
						ToolID:   toolID,
						ToolName: name,
					}, nil) {
						return
					}
				}
				if argDelta != "" {
					toolArgs[toolID].WriteString(argDelta)
					if !yield(llm.StreamEvent{
						Type:   llm.SEToolInputJSON,
						Text:   argDelta,
						ToolID: toolID,
					}, nil) {
						return
					}
				}
			}

			// stop_reason (field 5)
			if sr := fieldUint64(fields, 5); sr != 0 {
				switch sr {
				case stopEndTurn:
					stopReason = "end_turn"
				case stopMaxToks:
					stopReason = "max_tokens"
				case stopToolUse:
					stopReason = "tool_use"
				}
			}

			// usage (field 7)
			if usageData := fieldSubmsg(fields, 7); usageData != nil {
				uFields, _ := decodeFields(usageData)
				usage.InputTokens = int(fieldInt64(uFields, 2))
				usage.OutputTokens = int(fieldInt64(uFields, 3))
				usage.CacheWriteTokens = int(fieldInt64(uFields, 4))
				usage.CacheReadTokens = int(fieldInt64(uFields, 5))
			}
		}

		// Emit message_delta with stop_reason and usage
		yield(llm.StreamEvent{
			Type:       llm.SEMessageDelta,
			StopReason: stopReason,
			Usage:      usage,
		}, nil)
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

// Complete performs a non-streaming request by collecting the stream into a
// single Message.
func (p *provider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	var (
		msg       llm.Message
		blocks    []llm.ContentBlock
		usage     llm.Usage
		stopRsn   string
		textBuf   strings.Builder
		thinkBuf  strings.Builder
		thinkSig  string
		toolCalls []llm.ContentBlock
		// per-tool argument accumulators
		toolArgBufs = make(map[string]*strings.Builder)
		toolNameMap = make(map[string]string)
	)

	for ev, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		switch ev.Type {
		case llm.SETextDelta:
			textBuf.WriteString(ev.Text)
		case llm.SEThinkingDelta:
			thinkBuf.WriteString(ev.Text)
		case llm.SEThinkingSignature:
			thinkSig = ev.Text
		case llm.SEToolUseStart:
			toolNameMap[ev.ToolID] = ev.ToolName
			toolArgBufs[ev.ToolID] = &strings.Builder{}
		case llm.SEToolInputJSON:
			if buf, ok := toolArgBufs[ev.ToolID]; ok {
				buf.WriteString(ev.Text)
			}
		case llm.SEMessageDelta:
			stopRsn = ev.StopReason
			usage = ev.Usage
		}
	}

	if thinkBuf.Len() > 0 {
		blocks = append(blocks, llm.ContentBlock{
			Type:      llm.BlockThinking,
			Thinking:  thinkBuf.String(),
			Signature: thinkSig,
		})
	}
	if textBuf.Len() > 0 {
		blocks = append(blocks, llm.TextBlock(textBuf.String()))
	}
	for id, argBuf := range toolArgBufs {
		input := json.RawMessage(argBuf.String())
		if !json.Valid(input) {
			input = json.RawMessage("{}")
		}
		toolCalls = append(toolCalls, llm.ContentBlock{
			Type:  llm.BlockToolUse,
			ID:    id,
			Name:  toolNameMap[id],
			Input: input,
		})
	}
	blocks = append(blocks, toolCalls...)

	msg = llm.Message{Role: llm.RoleAssistant, Content: blocks}
	return msg, stopRsn, usage, nil
}

// buildRequest encodes CompletionRequest into GetChatMessageRequest protobuf.
func (p *provider) buildRequest(req llm.CompletionRequest) ([]byte, error) {
	sessionID := randomUUID()

	// Metadata (field 1)
	meta := make([]byte, 0, 256)
	meta = append(meta, encodeString(1, ideName)...)
	meta = append(meta, encodeString(2, ideVersion)...)
	meta = append(meta, encodeString(3, p.cfg.APIKey)...)
	meta = append(meta, encodeString(4, "en_US")...)
	meta = append(meta, encodeString(5, "linux")...)
	meta = append(meta, encodeString(7, ideVersion)...)
	meta = append(meta, encodeString(8, "x86_64")...)
	meta = append(meta, encodeUvarint(9, 1)...)
	meta = append(meta, encodeString(10, sessionID)...)
	meta = append(meta, encodeString(12, ideName)...)
	meta = append(meta, encodeString(26, planName)...)
	meta = append(meta, encodeString(28, ideName)...)

	body := make([]byte, 0, 4096)
	body = append(body, encodeSubmsg(1, meta)...)

	// system_prompt (field 2)
	system := joinSystem(req.System)
	if system != "" {
		body = append(body, encodeString(2, system)...)
	}

	// chat_messages (field 3, repeated)
	for _, msg := range req.Messages {
		prompts, err := p.encodeMessage(msg)
		if err != nil {
			return nil, err
		}
		for _, prompt := range prompts {
			body = append(body, encodeSubmsg(3, prompt)...)
		}
	}

	// request_type (field 7) = CASCADE
	body = append(body, encodeUvarint(7, requestTypeCascade)...)

	// tools (field 10, repeated)
	for _, tool := range req.Tools {
		td := make([]byte, 0, 128)
		td = append(td, encodeString(1, tool.Name)...)
		td = append(td, encodeString(2, tool.Description)...)
		td = append(td, encodeString(3, marshalToolSchema(tool.InputSchema))...)
		body = append(body, encodeSubmsg(10, td)...)
	}

	// cascade_id (field 16)
	body = append(body, encodeString(16, randomUUID())...)

	// chat_model_uid (field 21)
	body = append(body, encodeString(21, p.cfg.Model)...)

	return body, nil
}

// encodeMessage converts one norma Message into one or more ChatMessagePrompt
// protobuf blobs.
func (p *provider) encodeMessage(msg llm.Message) ([][]byte, error) {
	var results [][]byte

	if msg.Role == llm.RoleUser {
		prompt := p.encodePrompt(sourceUser, msg.Content)
		results = append(results, prompt)
		return results, nil
	}

	// Assistant message: may contain text, thinking, and tool_use blocks.
	// Text/thinking go in one prompt; tool results go in separate prompts.
	prompt := make([]byte, 0, 256)
	prompt = append(prompt, encodeString(1, randomUUID())...)
	prompt = append(prompt, encodeUvarint(2, sourceAssistant)...)

	var textBuf strings.Builder
	for _, block := range msg.Content {
		switch block.Type {
		case llm.BlockText:
			textBuf.WriteString(block.Text)
		case llm.BlockThinking:
			if block.Thinking != "" {
				prompt = append(prompt, encodeString(11, block.Thinking)...)
			}
			if block.Signature != "" {
				prompt = append(prompt, encodeString(12, block.Signature)...)
			}
		case llm.BlockToolUse:
			tc := make([]byte, 0, 64)
			tc = append(tc, encodeString(1, block.ID)...)
			tc = append(tc, encodeString(2, block.Name)...)
			inputStr := "{}"
			if len(block.Input) > 0 {
				inputStr = string(block.Input)
			}
			tc = append(tc, encodeString(3, inputStr)...)
			prompt = append(prompt, encodeSubmsg(6, tc)...)
		case llm.BlockToolResult:
			// Tool results are separate source=4 messages
			toolPrompt := make([]byte, 0, 128)
			toolPrompt = append(toolPrompt, encodeString(1, randomUUID())...)
			toolPrompt = append(toolPrompt, encodeUvarint(2, sourceTool)...)
			var toolText strings.Builder
			for _, sub := range block.Content {
				if sub.Type == llm.BlockText {
					toolText.WriteString(sub.Text)
				}
			}
			toolPrompt = append(toolPrompt, encodeString(3, toolText.String())...)
			toolPrompt = append(toolPrompt, encodeString(7, block.ToolUseID)...)
			results = append(results, toolPrompt)
		}
	}
	prompt = append(prompt, encodeString(3, textBuf.String())...)
	// Insert assistant prompt before tool results
	results = append([][]byte{prompt}, results...)
	return results, nil
}

func (p *provider) encodePrompt(source uint64, blocks []llm.ContentBlock) []byte {
	prompt := make([]byte, 0, 256)
	prompt = append(prompt, encodeString(1, randomUUID())...)
	prompt = append(prompt, encodeUvarint(2, source)...)
	var textBuf strings.Builder
	for _, block := range blocks {
		if block.Type == llm.BlockText {
			textBuf.WriteString(block.Text)
		}
	}
	prompt = append(prompt, encodeString(3, textBuf.String())...)
	return prompt
}

func joinSystem(segs []string) string {
	parts := make([]string, 0, len(segs))
	for _, s := range segs {
		s = strings.TrimSpace(s)
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n\n")
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
