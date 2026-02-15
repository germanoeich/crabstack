package tools

import (
	"encoding/json"
	"strings"

	"crabstack.local/projects/crab-sdk/toolhost"
	sdktypes "crabstack.local/projects/crab-sdk/types"
)

func okResponse(req toolhost.ToolCallRequest, toolName string, result any) toolhost.ToolCallResponse {
	payload, err := json.Marshal(result)
	if err != nil {
		return errorResponse(req, toolName, toolhost.ToolErrorCodeInternal, "failed to encode result", false)
	}
	return toolhost.ToolCallResponse{
		Version:  responseVersion(req),
		CallID:   strings.TrimSpace(req.CallID),
		ToolName: toolName,
		Status:   toolhost.ToolCallStatusOK,
		Result:   payload,
	}
}

func errorResponse(req toolhost.ToolCallRequest, toolName string, code string, message string, retryable bool) toolhost.ToolCallResponse {
	return toolhost.ToolCallResponse{
		Version:  responseVersion(req),
		CallID:   strings.TrimSpace(req.CallID),
		ToolName: toolName,
		Status:   toolhost.ToolCallStatusError,
		Error: &toolhost.ToolCallError{
			Code:      code,
			Message:   message,
			Retryable: retryable,
		},
	}
}

func responseVersion(req toolhost.ToolCallRequest) string {
	if version := strings.TrimSpace(req.Version); version != "" {
		return version
	}
	return sdktypes.VersionV1
}
