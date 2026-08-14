package certproto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	// ReconcileAcceptedHTTPStatus 是异步 reconcile 创建或复用任务时的状态码。
	ReconcileAcceptedHTTPStatus = 202
	// JobPollingHTTPStatus 是成功查询任务状态时的状态码。
	JobPollingHTTPStatus = 200
	// JobLocationHeader 是 202 响应携带任务轮询 URL 的响应头。
	JobLocationHeader = "Location"
	// JobRetryAfterHeader 是服务端建议下次轮询间隔的响应头。
	JobRetryAfterHeader = "Retry-After"
	// IdempotencyScope 明确幂等键在同一 domain 与 operation 内生效。
	IdempotencyScope = "domain_operation"
)

// ReconcileRequest 是 POST reconcile 的公共请求体。
//
// 同一 domain、operation 与 idempotency_key 必须始终返回原任务，包括已经结束的
// 任务。force 不改变重放语义；调用方要发起另一次强制执行，必须提供新的幂等键。
type ReconcileRequest struct {
	// IdempotencyKey 是调用方生成并在同一次逻辑请求的所有重试中复用的幂等键。
	IdempotencyKey string `json:"idempotency_key"`
	// Force 表示强制执行；新的强制执行不得复用旧任务的幂等键。
	Force bool `json:"force,omitempty"`
	// Operation 是可选的调用场景标识，空值等同于 reconcile。
	Operation string `json:"operation,omitempty"`
	// Reason 是可选的操作原因。
	Reason string `json:"reason,omitempty"`
}

// Validate 严格校验 reconcile 请求体。
func (r ReconcileRequest) Validate() error {
	if err := ValidateIdempotencyKey(r.IdempotencyKey); err != nil {
		return err
	}
	if len(r.Operation) > 64 || hasControl(r.Operation) {
		return protocolError(ErrorCodeInvalidRequest, "operation 长度不能超过 64 字节且不能包含控制字符")
	}
	if len(r.Reason) > 256 || hasControl(r.Reason) {
		return protocolError(ErrorCodeInvalidRequest, "reason 长度不能超过 256 字节且不能包含控制字符")
	}
	return nil
}

// ValidateForNewAttempt 校验请求是否可以相对旧幂等键发起一次新执行。
// 普通重放可以继续使用旧键；只有要再次执行 force 时才要求新键。
func (r ReconcileRequest) ValidateForNewAttempt(previousIdempotencyKey string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Force && previousIdempotencyKey != "" && r.IdempotencyKey == previousIdempotencyKey {
		return protocolError(ErrorCodeConflict, "新的 force 执行必须使用新的 idempotency_key")
	}
	return nil
}

// UnmarshalJSON 严格解码并校验 reconcile 请求，拒绝未知字段。
func (r *ReconcileRequest) UnmarshalJSON(data []byte) error {
	type requestJSON ReconcileRequest
	var decoded requestJSON
	if err := unmarshalStrictJSON(data, &decoded); err != nil {
		return err
	}
	request := ReconcileRequest(decoded)
	if err := request.Validate(); err != nil {
		return err
	}
	*r = request
	return nil
}

// MarshalJSON 在编码边界校验 reconcile 请求。
func (r ReconcileRequest) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type requestJSON ReconcileRequest
	return json.Marshal(requestJSON(r))
}

// ValidateJobID 校验任务 ID 是否为安全、非空的不透明单段标识。
func ValidateJobID(id string) error {
	if isPathTraversal(id) || id == "." || id == ".." {
		return protocolError(ErrorCodePathTraversal, "job id 不能包含路径分隔符或路径穿越片段")
	}
	if err := validatePathSegment(id); err != nil || len(id) > MaxJobIDLength {
		return protocolError(ErrorCodeInvalidJobID, "job id 必须是长度不超过 128 字节的单段标识")
	}
	for i := 0; i < len(id); i++ {
		if !isUnreserved(id[i]) {
			return protocolError(ErrorCodeInvalidJobID, "job id 只能包含 ASCII 字母、数字、-、.、_ 或 ~")
		}
	}
	return nil
}

// ValidateIdempotencyKey 校验幂等键非空、长度受限且只包含可见 ASCII 字符。
func ValidateIdempotencyKey(key string) error {
	if key == "" || len(key) > MaxIdempotencyKeyLength {
		return protocolError(ErrorCodeInvalidIdempotencyKey, "idempotency_key 必填且长度不能超过 128 字节")
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return protocolError(ErrorCodeInvalidIdempotencyKey, "idempotency_key 只能包含可见 ASCII 字符且不能包含空白")
		}
	}
	return nil
}

// ValidateDomain 校验规范化的小写 DNS 主机名，拒绝通配符、IP、端口和路径。
func ValidateDomain(domain string) error {
	invalid := func(message string) error { return protocolError(ErrorCodeInvalidDomain, message) }
	if domain == "" {
		return invalid("domain 不能为空")
	}
	if len(domain) > MaxDomainLength || domain != strings.ToLower(domain) || strings.TrimSpace(domain) != domain ||
		strings.Contains(domain, "*") || strings.ContainsAny(domain, "/\\") || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return invalid("domain 必须是规范化的小写 DNS 主机名")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid("domain 包含无效的 DNS 标签")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return invalid("domain 只能包含小写 ASCII 字母、数字、连字符和点")
			}
		}
	}
	return nil
}

// IsTerminal 判断任务状态是否为不可再变化的终态。
func (s JobState) IsTerminal() bool {
	switch s {
	case JobStateSucceeded, JobStateFailed, JobStateCancelled:
		return true
	default:
		return false
	}
}

// Validate 校验任务生命周期状态。
func (s JobState) Validate() error {
	switch s {
	case JobStateQueued, JobStateRunning, JobStateSucceeded, JobStateFailed, JobStateCancelled:
		return nil
	default:
		return protocolError(ErrorCodeInvalidJobStatus, "无效的任务状态: "+string(s))
	}
}

// IsTerminal 判断当前任务是否已经进入可持续查询和复用的终态。
func (j JobStatus) IsTerminal() bool { return j.State.IsTerminal() }

// Validate 严格校验任务状态及字段间约束。
func (j JobStatus) Validate() error {
	if err := ValidateJobID(j.ID); err != nil {
		return err
	}
	if err := j.State.Validate(); err != nil {
		return err
	}
	if (j.Generation == "") != (j.Revision == 0) {
		return protocolError(ErrorCodeInvalidJobStatus, "generation 与 revision 必须同时提供或同时省略")
	}
	if j.Generation != "" {
		if err := j.Generation.Validate(); err != nil {
			return err
		}
		if err := j.Revision.Validate(); err != nil {
			return err
		}
	}
	if err := validateTimeOrder(j.StartedAt, j.FinishedAt); err != nil {
		return err
	}
	if j.StartedAt != nil && j.StartedAt.Before(j.CreatedAt) {
		return protocolError(ErrorCodeInvalidJobStatus, "started_at 不能早于 created_at")
	}
	if j.FinishedAt != nil && j.FinishedAt.Before(j.CreatedAt) {
		return protocolError(ErrorCodeInvalidJobStatus, "finished_at 不能早于 created_at")
	}
	if len(j.Message) > 1024 || hasControl(j.Message) {
		return protocolError(ErrorCodeInvalidJobStatus, "message 长度不能超过 1024 字节且不能包含控制字符")
	}
	if j.Error != nil {
		if j.Error.Code == "" {
			return protocolError(ErrorCodeInvalidJobStatus, "error.code 不能为空")
		}
		if j.ErrorCode != "" && j.ErrorCode != j.Error.Code {
			return protocolError(ErrorCodeInvalidJobStatus, "error_code 与 error.code 不一致")
		}
		if j.Retryable != j.Error.Retryable && (j.Retryable || j.Error.Retryable) {
			return protocolError(ErrorCodeInvalidJobStatus, "retryable 与 error.retryable 不一致")
		}
	}
	errorCode := j.ErrorCode
	if errorCode == "" && j.Error != nil {
		errorCode = j.Error.Code
	}
	if j.State == JobStateFailed && errorCode == "" {
		return protocolError(ErrorCodeInvalidJobStatus, "失败任务必须包含 error_code")
	}
	if j.NextAttemptAt != nil {
		if !j.Retryable || j.NextAttemptAt.IsZero() {
			return protocolError(ErrorCodeInvalidJobStatus, "next_attempt_at 只适用于可重试任务")
		}
		if !j.CreatedAt.IsZero() && j.NextAttemptAt.Before(j.CreatedAt) {
			return protocolError(ErrorCodeInvalidJobStatus, "next_attempt_at 不能早于 created_at")
		}
	}
	return nil
}

func canonicalJobStatus(j JobStatus) JobStatus {
	if j.Error != nil {
		if j.ErrorCode == "" {
			j.ErrorCode = j.Error.Code
		}
		if !j.Retryable {
			j.Retryable = j.Error.Retryable
		}
	}
	return j
}

// UnmarshalJSON 严格解码并校验任务状态，兼容旧 error 对象并补齐扁平字段。
func (j *JobStatus) UnmarshalJSON(data []byte) error {
	type statusJSON JobStatus
	var decoded statusJSON
	if err := unmarshalStrictJSON(data, &decoded); err != nil {
		return err
	}
	status := canonicalJobStatus(JobStatus(decoded))
	if err := status.Validate(); err != nil {
		return err
	}
	*j = status
	return nil
}

// MarshalJSON 在编码边界校验任务状态并补齐兼容错误字段。
func (j JobStatus) MarshalJSON() ([]byte, error) {
	j = canonicalJobStatus(j)
	if err := j.Validate(); err != nil {
		return nil, err
	}
	type statusJSON JobStatus
	return json.Marshal(statusJSON(j))
}

// Validate 校验 202 响应中任务与轮询 URL 的一致性。
func (r JobAcceptedResponse) Validate() error {
	if err := r.Job.Validate(); err != nil {
		return err
	}
	expected, err := JobURLPath(r.Job.ID)
	if err != nil {
		return err
	}
	if r.Location != expected {
		return protocolError(ErrorCodeInvalidRequest, "location 必须指向响应中的任务")
	}
	return nil
}

// Validate 校验部署生命周期状态。
func (s DeploymentState) Validate() error {
	switch s {
	case DeploymentStatePending, DeploymentStateDeploying, DeploymentStateSucceeded, DeploymentStateFailed, DeploymentStateSkipped:
		return nil
	default:
		return protocolError(ErrorCodeInvalidDeploymentReport, "无效的部署状态: "+string(s))
	}
}

// Validate 严格校验部署回报；domain、generation、revision 均必须由调用方提供。
func (r DeploymentReport) Validate() error {
	if err := ValidateDomain(r.Domain); err != nil {
		return err
	}
	if err := r.Generation.Validate(); err != nil {
		return err
	}
	if err := r.Revision.Validate(); err != nil {
		return err
	}
	if err := validateText(r.Target, "target", 128, true); err != nil {
		return err
	}
	if err := validateText(r.Message, "message", 1024, false); err != nil {
		return err
	}
	if err := r.State.Validate(); err != nil {
		return err
	}
	if err := validateTimeOrder(r.StartedAt, r.FinishedAt); err != nil {
		return err
	}
	switch r.State {
	case DeploymentStateSucceeded, DeploymentStateSkipped:
		if !r.Success || r.Error != nil {
			return protocolError(ErrorCodeInvalidDeploymentReport, "成功或跳过的部署必须 success=true 且不能包含 error")
		}
	case DeploymentStateFailed:
		if r.Success || r.Error == nil || r.Error.Code == "" {
			return protocolError(ErrorCodeInvalidDeploymentReport, "失败部署必须 success=false 并包含结构化 error")
		}
	case DeploymentStatePending, DeploymentStateDeploying:
		if r.Success || r.Error != nil {
			return protocolError(ErrorCodeInvalidDeploymentReport, "非终态部署必须 success=false 且不能包含 error")
		}
	}
	return nil
}

// ValidateForDomain 校验回报 domain 必须与 URL 路径中的 domain 完全一致。
func (r DeploymentReport) ValidateForDomain(domain string) error {
	if err := ValidateDomain(domain); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Domain != domain {
		return protocolError(ErrorCodeConflict, "部署回报 domain 与请求路径不一致")
	}
	return nil
}

// UnmarshalJSON 严格解码并校验部署回报，拒绝缺失调用方版本信息。
func (r *DeploymentReport) UnmarshalJSON(data []byte) error {
	type reportJSON DeploymentReport
	var decoded reportJSON
	if err := unmarshalStrictJSON(data, &decoded); err != nil {
		return err
	}
	report := DeploymentReport(decoded)
	if err := report.Validate(); err != nil {
		return err
	}
	*r = report
	return nil
}

// MarshalJSON 在编码边界严格校验部署回报。
func (r DeploymentReport) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	type reportJSON DeploymentReport
	return json.Marshal(reportJSON(r))
}

func unmarshalStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return protocolError(ErrorCodeInvalidRequest, "JSON 格式不合法: "+err.Error())
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return protocolError(ErrorCodeInvalidRequest, "JSON 只能包含一个值")
		}
		return protocolError(ErrorCodeInvalidRequest, "JSON 格式不合法: "+err.Error())
	}
	return nil
}

func validateText(value, field string, max int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return protocolError(ErrorCodeInvalidDeploymentReport, field+" 不能为空")
	}
	if len(value) > max || hasControl(value) {
		return protocolError(ErrorCodeInvalidDeploymentReport, fmt.Sprintf("%s 长度不能超过 %d 字节且不能包含控制字符", field, max))
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func validateTimeOrder(startedAt, finishedAt *time.Time) error {
	if startedAt != nil && startedAt.IsZero() {
		return protocolError(ErrorCodeInvalidRequest, "started_at 不能是零时间")
	}
	if finishedAt != nil && finishedAt.IsZero() {
		return protocolError(ErrorCodeInvalidRequest, "finished_at 不能是零时间")
	}
	if startedAt != nil && finishedAt != nil && finishedAt.Before(*startedAt) {
		return protocolError(ErrorCodeInvalidRequest, "finished_at 不能早于 started_at")
	}
	return nil
}
