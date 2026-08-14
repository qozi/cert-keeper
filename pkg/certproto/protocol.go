// Package certproto 定义 CertKeeper v2 服务端与客户端共用的公共协议。
//
// 本包只包含协议数据结构、常量和纯函数，不依赖 HTTP、磁盘或证书签发实现。
package certproto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// APIVersion 是公共协议的主版本标识。
const APIVersion = "v2"

const (
	// MaxGenerationIDLength 是 generation 标识的最大字节数。
	MaxGenerationIDLength = 128
	// MaxJobIDLength 是任务 ID 的最大字节数。
	MaxJobIDLength = 128
	// MaxIdempotencyKeyLength 是幂等键的最大字节数。
	MaxIdempotencyKeyLength = 128
	// MaxDomainLength 是 DNS 域名的最大字节数。
	MaxDomainLength = 253
)

// ErrorCode 是协议层结构化错误码。
type ErrorCode string

const (
	// ErrorCodeInvalidRequest 表示请求字段缺失或格式不正确。
	ErrorCodeInvalidRequest ErrorCode = "invalid_request"
	// ErrorCodeInvalidGeneration 表示 generation 不符合单段标识契约。
	ErrorCodeInvalidGeneration ErrorCode = "invalid_generation"
	// ErrorCodeInvalidRevision 表示 revision 不符合版本契约。
	ErrorCodeInvalidRevision ErrorCode = "invalid_revision"
	// ErrorCodeInvalidJobID 表示任务 ID 不符合单段标识契约。
	ErrorCodeInvalidJobID ErrorCode = "invalid_job_id"
	// ErrorCodeInvalidIdempotencyKey 表示幂等键缺失或格式不正确。
	ErrorCodeInvalidIdempotencyKey ErrorCode = "invalid_idempotency_key"
	// ErrorCodeInvalidDomain 表示域名不是规范化的小写 DNS 主机名。
	ErrorCodeInvalidDomain ErrorCode = "invalid_domain"
	// ErrorCodeInvalidPathSegment 表示 URL 路径段为空或含有控制字符。
	ErrorCodeInvalidPathSegment ErrorCode = "invalid_path_segment"
	// ErrorCodePathTraversal 表示路径段含有路径分隔符或路径穿越片段。
	ErrorCodePathTraversal ErrorCode = "path_traversal"
	// ErrorCodeInvalidFileName 表示文件名为空或格式不正确。
	ErrorCodeInvalidFileName ErrorCode = "invalid_file_name"
	// ErrorCodeUnknownFile 表示文件名不在固定文件集合中。
	ErrorCodeUnknownFile ErrorCode = "unknown_file"
	// ErrorCodeDuplicateFile 表示 manifest 中出现重复文件名。
	ErrorCodeDuplicateFile ErrorCode = "duplicate_file"
	// ErrorCodeInvalidManifest 表示文件 manifest 的元数据不正确。
	ErrorCodeInvalidManifest ErrorCode = "invalid_manifest"
	// ErrorCodeInvalidJobStatus 表示任务状态字段不一致或格式不正确。
	ErrorCodeInvalidJobStatus ErrorCode = "invalid_job_status"
	// ErrorCodeInvalidCapabilities 表示能力声明缺少必需字段或 URL。
	ErrorCodeInvalidCapabilities ErrorCode = "invalid_capabilities"
	// ErrorCodeInvalidDeploymentReport 表示部署回报字段缺失或不一致。
	ErrorCodeInvalidDeploymentReport ErrorCode = "invalid_deployment_report"
	// ErrorCodeUnauthorized 表示请求未通过身份认证。
	ErrorCodeUnauthorized ErrorCode = "unauthorized"
	// ErrorCodeForbidden 表示已认证但没有操作权限。
	ErrorCodeForbidden ErrorCode = "forbidden"
	// ErrorCodeNotFound 表示请求的证书或任务不存在。
	ErrorCodeNotFound ErrorCode = "not_found"
	// ErrorCodeConflict 表示请求与当前证书版本冲突。
	ErrorCodeConflict ErrorCode = "conflict"
	// ErrorCodeJobFailed 表示证书任务执行失败。
	ErrorCodeJobFailed ErrorCode = "job_failed"
	// ErrorCodeDeploymentFailed 表示部署、校验或 reload 失败。
	ErrorCodeDeploymentFailed ErrorCode = "deployment_failed"
	// ErrorCodeInternal 表示服务端未分类的内部错误。
	ErrorCodeInternal ErrorCode = "internal"
)

// ErrorResponse 是协议统一的结构化错误响应。
type ErrorResponse struct {
	// Code 是机器可判定的稳定错误码。
	Code ErrorCode `json:"code"`
	// Message 是面向日志或用户的错误说明，不应作为程序判断依据。
	Message string `json:"message"`
	// Retryable 表示调用方是否可以在稍后重试。
	Retryable bool `json:"retryable,omitempty"`
	// Details 提供可选的结构化错误上下文。
	Details map[string]string `json:"details,omitempty"`
}

// Error 使 ErrorResponse 也可以作为 Go error 返回。
func (e ErrorResponse) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GenerationID 是证书 generation 的不透明单段标识。
//
// 合法值只允许 ASCII 字母、数字、连字符、点、下划线和波浪号，且不能是
// "." 或 ".."。该约束使 generation 可以安全地出现在 URL 路径和文件目录名中。
type GenerationID string

// Revision 是 generation 内单调递增的证书版本号，从 1 开始。
type Revision uint64

// CertificateVersion 表示一组证书产物的稳定版本契约。
type CertificateVersion struct {
	// Generation 标识逻辑证书配置的一代版本。
	Generation GenerationID `json:"generation"`
	// Revision 标识该 generation 内的具体产物版本。
	Revision Revision `json:"revision"`
}

// Validate 校验证书版本的 generation 和 revision。
func (v CertificateVersion) Validate() error {
	if err := v.Generation.Validate(); err != nil {
		return err
	}
	return v.Revision.Validate()
}

// Validate 校验 generation 是否为安全的单段标识。
func (g GenerationID) Validate() error { return ValidateGenerationID(string(g)) }

// ValidateGenerationID 校验 generation ID 的单段标识契约。
func ValidateGenerationID(id string) error {
	if isPathTraversal(id) || id == "." || id == ".." {
		return protocolError(ErrorCodePathTraversal, "generation 不能包含路径分隔符或路径穿越片段")
	}
	if err := validatePathSegment(id); err != nil {
		return protocolError(ErrorCodeInvalidGeneration, "generation 必须是非空的单段标识")
	}
	if len(id) > MaxGenerationIDLength {
		return protocolError(ErrorCodeInvalidGeneration, "generation 长度不能超过 128 字节")
	}
	for i := 0; i < len(id); i++ {
		if !isUnreserved(id[i]) {
			return protocolError(ErrorCodeInvalidGeneration, "generation 只能包含 ASCII 字母、数字、-、.、_ 或 ~")
		}
	}
	return nil
}

// Validate 校验 revision 必须是从 1 开始的非零版本号。
func (r Revision) Validate() error { return ValidateRevision(uint64(r)) }

// ValidateRevision 校验 revision 必须大于零。
func ValidateRevision(revision uint64) error {
	if revision == 0 {
		return protocolError(ErrorCodeInvalidRevision, "revision 必须大于 0")
	}
	return nil
}

// UnmarshalJSON 在解码边界拒绝不安全的 generation。
func (g *GenerationID) UnmarshalJSON(data []byte) error {
	var id string
	if err := json.Unmarshal(data, &id); err != nil {
		return protocolError(ErrorCodeInvalidGeneration, "generation 必须是字符串")
	}
	if err := ValidateGenerationID(id); err != nil {
		return err
	}
	*g = GenerationID(id)
	return nil
}

// MarshalJSON 在编码边界拒绝不安全的 generation。
func (g GenerationID) MarshalJSON() ([]byte, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(string(g))
}

// FileName 是固定证书文件集合中的文件名。
type FileName string

const (
	// FileCert 是叶子证书文件名。
	FileCert FileName = "cert.pem"
	// FileKey 是私钥文件名。
	FileKey FileName = "key.pem"
	// FileFullchain 是完整证书链文件名。
	FileFullchain FileName = "fullchain.pem"
	// FileCA 是 CA 证书文件名。
	FileCA FileName = "ca.pem"
	// FileTimeLog 是签发时间日志文件名。
	FileTimeLog FileName = "time.log"
)

var fixedFileNames = [...]FileName{
	FileCert,
	FileKey,
	FileFullchain,
	FileCA,
	FileTimeLog,
}

// FixedFileNames 返回 v2 允许的固定文件名集合。
func FixedFileNames() []FileName {
	return append([]FileName(nil), fixedFileNames[:]...)
}

// IsFixedFileName 判断 name 是否属于固定文件集合。
func IsFixedFileName(name string) bool {
	for _, fixed := range fixedFileNames {
		if name == string(fixed) {
			return true
		}
	}
	return false
}

// Validate 校验固定文件名。
func (f FileName) Validate() error { return ValidateFileName(string(f)) }

// ValidateFileName 校验文件名非空、不含路径分隔符且属于固定集合。
func ValidateFileName(name string) error {
	if name == "" {
		return protocolError(ErrorCodeInvalidFileName, "文件名不能为空")
	}
	if isPathTraversal(name) || name == "." || name == ".." {
		return protocolError(ErrorCodePathTraversal, "文件名不能包含路径分隔符或路径穿越片段")
	}
	if !IsFixedFileName(name) {
		return protocolError(ErrorCodeUnknownFile, "未知证书文件名: "+name)
	}
	return nil
}

// FileManifest 描述一个证书文件产物。
type FileManifest struct {
	// Name 是固定文件集合中的文件名。
	Name string `json:"name"`
	// Size 是文件字节数，不能为负数。
	Size int64 `json:"size"`
	// SHA256 是文件内容的 64 位小写十六进制 SHA-256 摘要。
	SHA256 string `json:"sha256"`
}

// Validate 校验文件 manifest 项的文件名和摘要元数据。
func (f FileManifest) Validate() error {
	if err := ValidateFileName(f.Name); err != nil {
		return err
	}
	if f.Size < 0 {
		return protocolError(ErrorCodeInvalidManifest, "文件大小不能为负数")
	}
	if len(f.SHA256) != 64 || hex.DecodedLen(len(f.SHA256)) != 32 || !isLowerHex(f.SHA256) {
		return protocolError(ErrorCodeInvalidManifest, "SHA256 必须是 64 位小写十六进制字符串")
	}
	return nil
}

// UnmarshalJSON 在解码边界校验单个 manifest 项。
func (f *FileManifest) UnmarshalJSON(data []byte) error {
	type fileManifestJSON FileManifest
	var decoded fileManifestJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if err := FileManifest(decoded).Validate(); err != nil {
		return err
	}
	*f = FileManifest(decoded)
	return nil
}

// MarshalJSON 在编码边界校验单个 manifest 项。
func (f FileManifest) MarshalJSON() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	type fileManifestJSON FileManifest
	return json.Marshal(fileManifestJSON(f))
}

// CertificateManifest 是证书文件 manifest，文件名不能重复。
type CertificateManifest []FileManifest

// Manifest 是 CertificateManifest 的简短别名。
type Manifest = CertificateManifest

// Validate 校验 manifest 中的每个文件并拒绝重复文件名。
func (m CertificateManifest) Validate() error {
	seen := make(map[string]struct{}, len(m))
	for _, file := range m {
		if err := file.Validate(); err != nil {
			return err
		}
		if _, exists := seen[file.Name]; exists {
			return protocolError(ErrorCodeDuplicateFile, "manifest 中存在重复文件名: "+file.Name)
		}
		seen[file.Name] = struct{}{}
	}
	return nil
}

// UnmarshalJSON 在解码边界校验整个 manifest，包括重复文件名。
func (m *CertificateManifest) UnmarshalJSON(data []byte) error {
	var decoded []FileManifest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	manifest := CertificateManifest(decoded)
	if err := manifest.Validate(); err != nil {
		return err
	}
	*m = manifest
	return nil
}

// MarshalJSON 在编码边界校验整个 manifest，包括重复文件名。
func (m CertificateManifest) MarshalJSON() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal([]FileManifest(m))
}

// JobState 是证书任务的生命周期状态。
type JobState string

const (
	// JobStateQueued 表示任务已创建但尚未执行。
	JobStateQueued JobState = "queued"
	// JobStateRunning 表示任务正在执行。
	JobStateRunning JobState = "running"
	// JobStateSucceeded 表示任务成功完成。
	JobStateSucceeded JobState = "succeeded"
	// JobStateFailed 表示任务执行失败。
	JobStateFailed JobState = "failed"
	// JobStateCancelled 表示任务被取消。
	JobStateCancelled JobState = "cancelled"
)

// JobStatus 描述一次申请、续签或 reconcile 任务的执行状态。
type JobStatus struct {
	// ID 是任务的稳定标识。
	ID string `json:"id"`
	// State 是任务当前生命周期状态。
	State JobState `json:"state"`
	// Generation 是任务操作的证书 generation。
	Generation GenerationID `json:"generation,omitempty"`
	// Revision 是任务生成或操作的证书 revision。
	Revision Revision `json:"revision,omitempty"`
	// Message 是补充状态说明。
	Message string `json:"message,omitempty"`
	// Retryable 表示当前失败是否允许调用方稍后重试。
	Retryable bool `json:"retryable,omitempty"`
	// ErrorCode 是失败任务的稳定错误码。
	ErrorCode ErrorCode `json:"error_code,omitempty"`
	// NextAttemptAt 是服务端计划下一次尝试的时间。
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	// Error 是任务失败时的结构化错误。
	// Deprecated: 新调用方应优先读取 ErrorCode 和 Retryable。
	Error *ErrorResponse `json:"error,omitempty"`
	// CreatedAt 是任务创建时间。
	CreatedAt time.Time `json:"created_at,omitempty"`
	// StartedAt 是任务开始执行时间。
	StartedAt *time.Time `json:"started_at,omitempty"`
	// FinishedAt 是任务结束时间。
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// CertificateState 是证书产物的状态。
type CertificateState string

const (
	// CertificateStateUnknown 表示状态尚未确定。
	CertificateStateUnknown CertificateState = "unknown"
	// CertificateStateMissing 表示证书产物不存在或不完整。
	CertificateStateMissing CertificateState = "missing"
	// CertificateStateValid 表示证书产物存在且仍在有效期内。
	CertificateStateValid CertificateState = "valid"
	// CertificateStateExpired 表示证书已过期。
	CertificateStateExpired CertificateState = "expired"
)

// CertificateStatus 描述某个证书 generation/revision 的当前状态。
type CertificateStatus struct {
	// Domain 是证书对应的主域名。
	Domain string `json:"domain"`
	// Generation 是当前证书产物所属 generation。
	Generation GenerationID `json:"generation,omitempty"`
	// Revision 是当前证书产物版本。
	Revision Revision `json:"revision,omitempty"`
	// State 是证书产物状态。
	State CertificateState `json:"state"`
	// NotAfter 是证书的失效时间。
	NotAfter time.Time `json:"not_after"`
	// TimeLog 是服务端记录的签发时间戳；没有记录时为 0。
	TimeLog int64 `json:"time_log,omitempty"`
	// Files 是当前可下载文件的 manifest。
	Files CertificateManifest `json:"files"`
	// Exists 表示证书主产物是否存在。
	Exists bool `json:"exists"`
	// Message 是补充状态说明。
	Message string `json:"message,omitempty"`
}

// CertStatus 是 CertificateStatus 的兼容性别名。
type CertStatus = CertificateStatus

// DeploymentState 是客户端部署证书后的结果状态。
type DeploymentState string

const (
	// DeploymentStatePending 表示部署尚未开始。
	DeploymentStatePending DeploymentState = "pending"
	// DeploymentStateDeploying 表示文件已接收，正在校验或 reload。
	DeploymentStateDeploying DeploymentState = "deploying"
	// DeploymentStateSucceeded 表示部署及后续动作成功。
	DeploymentStateSucceeded DeploymentState = "succeeded"
	// DeploymentStateFailed 表示部署或后续动作失败。
	DeploymentStateFailed DeploymentState = "failed"
	// DeploymentStateSkipped 表示没有执行部署动作。
	DeploymentStateSkipped DeploymentState = "skipped"
)

// DeploymentReport 是客户端部署证书后的结构化回报。
type DeploymentReport struct {
	// Domain 是本次部署产物所属的规范化域名，必须由调用方明确提供。
	Domain string `json:"domain"`
	// Target 是部署目标的稳定名称或标识。
	Target string `json:"target,omitempty"`
	// State 是部署生命周期状态。
	State DeploymentState `json:"state"`
	// Success 表示部署流程是否成功。
	Success bool `json:"success"`
	// Generation 是部署产物所属 generation。
	Generation GenerationID `json:"generation,omitempty"`
	// Revision 是部署产物版本。
	Revision Revision `json:"revision,omitempty"`
	// Verified 表示部署后的证书校验命令是否成功。
	Verified bool `json:"verified,omitempty"`
	// Reloaded 表示服务 reload 动作是否成功。
	Reloaded bool `json:"reloaded,omitempty"`
	// Message 是部署结果说明。
	Message string `json:"message,omitempty"`
	// Error 是部署失败时的结构化错误。
	Error *ErrorResponse `json:"error,omitempty"`
	// StartedAt 是部署开始时间。
	StartedAt *time.Time `json:"started_at,omitempty"`
	// FinishedAt 是部署结束时间。
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ApplyResponse 是申请或续签操作的 v2 响应。
type ApplyResponse struct {
	// Success 表示申请或续签是否成功完成。
	Success bool `json:"success"`
	// Domain 是证书对应的主域名。
	Domain string `json:"domain"`
	// Generation 是本次操作产生或确认的 generation。
	Generation GenerationID `json:"generation"`
	// Revision 是本次操作产生或确认的 revision。
	Revision Revision `json:"revision"`
	// Renewed 表示是否实际执行了续签。
	Renewed bool `json:"renewed"`
	// Job 是申请任务的最终或当前状态。
	Job JobStatus `json:"job"`
	// Status 是申请完成后的证书状态。
	Status CertificateStatus `json:"status"`
	// Deployment 是可选的客户端部署回报。
	Deployment *DeploymentReport `json:"deployment,omitempty"`
	// Error 是失败时的结构化错误。
	Error *ErrorResponse `json:"error,omitempty"`
	// Message 是补充结果说明。
	Message string `json:"message,omitempty"`
}

// ReconcileResponse 是 reconcile 操作的 v2 响应。
type ReconcileResponse struct {
	// Success 表示 reconcile 是否成功完成。
	Success bool `json:"success"`
	// Domain 是证书对应的主域名。
	Domain string `json:"domain"`
	// Generation 是 reconcile 操作确认或产生的 generation。
	Generation GenerationID `json:"generation"`
	// Revision 是 reconcile 操作确认或产生的 revision。
	Revision Revision `json:"revision"`
	// Changed 表示 reconcile 是否改变了证书产物。
	Changed bool `json:"changed"`
	// Job 是 reconcile 任务的最终或当前状态。
	Job JobStatus `json:"job"`
	// Status 是 reconcile 完成后的证书状态。
	Status CertificateStatus `json:"status"`
	// Deployment 是可选的客户端部署回报。
	Deployment *DeploymentReport `json:"deployment,omitempty"`
	// Error 是失败时的结构化错误。
	Error *ErrorResponse `json:"error,omitempty"`
	// Message 是补充结果说明。
	Message string `json:"message,omitempty"`
}

// JobAcceptedResponse 是异步 reconcile 返回 HTTP 202 时的响应体。
// Location 指向可持续查询的任务 URL，终态任务也可以通过该 URL 查询。
type JobAcceptedResponse struct {
	// Job 是新建或按幂等键复用的任务状态。
	Job JobStatus `json:"job"`
	// Location 是任务轮询 URL。
	Location string `json:"location"`
	// Reused 表示响应复用了已有任务。
	Reused bool `json:"reused,omitempty"`
}

// AcceptedJobResponse 是 JobAcceptedResponse 的兼容性别名。
type AcceptedJobResponse = JobAcceptedResponse

func protocolError(code ErrorCode, message string) error {
	return ErrorResponse{Code: code, Message: message}
}

func validatePathSegment(segment string) error {
	if segment == "" {
		return protocolError(ErrorCodeInvalidPathSegment, "URL 路径段不能为空")
	}
	if isPathTraversal(segment) || segment == "." || segment == ".." {
		return protocolError(ErrorCodePathTraversal, "URL 路径段不能包含路径分隔符或路径穿越片段")
	}
	for i := 0; i < len(segment); i++ {
		if segment[i] < 0x20 || segment[i] == 0x7f {
			return protocolError(ErrorCodeInvalidPathSegment, "URL 路径段不能包含控制字符")
		}
	}
	return nil
}

func isPathTraversal(value string) bool {
	return strings.ContainsAny(value, "/\\")
}

func isUnreserved(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '-' || value == '.' || value == '_' || value == '~'
}

func isLowerHex(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			continue
		}
		if value[i] < 'a' || value[i] > 'f' {
			return false
		}
	}
	return true
}
