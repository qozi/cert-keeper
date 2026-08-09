// 本文件提供可空字符串的 JSON 序列化支持。
package store

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// JSONNullString 包装 sql.NullString，支持 JSON 字符串往返与 SQL 扫描。
type JSONNullString sql.NullString

// UnmarshalJSON 从 JSON 字符串反序列化，空字符串或 null 被视为无效。
func (n *JSONNullString) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		n.String = ""
		n.Valid = false
		return nil
	}
	if string(b) == "\"\"" {
		n.String = ""
		n.Valid = false
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	n.String = s
	n.Valid = s != ""
	return nil
}

// MarshalJSON 将 JSONNullString 序列化为 JSON 字符串。
func (n JSONNullString) MarshalJSON() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(n.String)
}

// Scan 实现 sql.Scanner 接口，从数据库扫描值。
func (n *JSONNullString) Scan(src any) error {
	ns := (*sql.NullString)(n)
	return ns.Scan(src)
}

// Value 实现 driver.Valuer 接口，返回数据库存储值。
func (n JSONNullString) Value() (driver.Value, error) {
	if !n.Valid {
		return nil, nil
	}
	return n.String, nil
}

// AsSQL 转回 sql.NullString 供 DB 操作使用。
func (n JSONNullString) AsSQL() sql.NullString {
	return sql.NullString(n)
}

var _ = errors.New
