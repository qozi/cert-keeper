package certproto

import "errors"

// HTTPStatusForErrorCode 将公共错误码映射为稳定的 HTTP 状态码。
// 未知错误码按 internal 处理，避免把服务端内部错误误报为客户端错误。
func HTTPStatusForErrorCode(code ErrorCode) int {
	switch code {
	case ErrorCodeInvalidRequest,
		ErrorCodeInvalidGeneration,
		ErrorCodeInvalidRevision,
		ErrorCodeInvalidJobID,
		ErrorCodeInvalidIdempotencyKey,
		ErrorCodeInvalidDomain,
		ErrorCodeInvalidPathSegment,
		ErrorCodePathTraversal,
		ErrorCodeInvalidFileName,
		ErrorCodeUnknownFile,
		ErrorCodeDuplicateFile,
		ErrorCodeInvalidManifest,
		ErrorCodeInvalidJobStatus,
		ErrorCodeInvalidCapabilities,
		ErrorCodeInvalidDeploymentReport:
		return 400
	case ErrorCodeUnauthorized:
		return 401
	case ErrorCodeForbidden:
		return 403
	case ErrorCodeNotFound:
		return 404
	case ErrorCodeConflict:
		return 409
	case ErrorCodeJobFailed, ErrorCodeDeploymentFailed, ErrorCodeInternal:
		return 500
	default:
		return 500
	}
}

// ErrorCodeHTTPStatus 是 HTTPStatusForErrorCode 的兼容性别名。
func ErrorCodeHTTPStatus(code ErrorCode) int { return HTTPStatusForErrorCode(code) }

// HTTPStatusForError 将结构化错误映射为 HTTP 状态码；非结构化错误按 internal 处理。
func HTTPStatusForError(err error) int {
	var response ErrorResponse
	if errors.As(err, &response) {
		return HTTPStatusForErrorCode(response.Code)
	}
	var responsePointer *ErrorResponse
	if errors.As(err, &responsePointer) && responsePointer != nil {
		return HTTPStatusForErrorCode(responsePointer.Code)
	}
	return HTTPStatusForErrorCode(ErrorCodeInternal)
}
