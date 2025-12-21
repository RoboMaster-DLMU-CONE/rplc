use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Error, Serialize, PartialEq)]
pub enum ValidationCode {
    // ---- Errors ----
    #[error("Packet名称 '{0}' 无效，必须符合 C++ 标识符规范")]
    InvalidPacketName(String),

    #[error("字段名 '{0}' 无效，必须符合 C++ 标识符规范")]
    InvalidFieldName(String),

    #[error("字段名 '{0}' 是 C++ 保留关键字")]
    KeywordCollision(String),

    #[error("字段名 '{0}' 重复定义")]
    DuplicateFieldName(String),

    #[error("Command ID '{0}' 格式错误，必须是 0-65535 的整数或十六进制")]
    InvalidCommandIdFormat(String),

    // ---- Warnings ----
    #[error("Packet名称 '{0}' 建议使用大驼峰命名法 (PascalCase)")]
    NamingConventionPacket(String),

    #[error("字段名 '{0}' 建议使用蛇形命名法 (snake_case)")]
    NamingConventionField(String),

    #[error("建议为字段 '{0}' 添加注释")]
    MissingComment(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: ValidationCode, // 具体错误枚举
    pub field: Option<String>, // 关联字段名
                              // pub span: Option<(usize, usize)>,
}

impl Diagnostic {
    pub fn error(code: ValidationCode, field: Option<String>) -> Self {
        Self {
            severity: Severity::Error,
            code,
            field,
        }
    }

    pub fn warning(code: ValidationCode, field: Option<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code,
            field,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_enum() {
        assert_eq!(format!("{:?}", Severity::Error), "Error");
        assert_eq!(format!("{:?}", Severity::Warning), "Warning");
        assert_eq!(Severity::Error, Severity::Error);
        assert_eq!(Severity::Warning, Severity::Warning);
        assert_ne!(Severity::Error, Severity::Warning);
    }

    #[test]
    fn test_validation_code_error_messages() {
        // Test error messages
        assert_eq!(
            ValidationCode::InvalidPacketName("TestPacket".to_string()).to_string(),
            "Packet名称 'TestPacket' 无效，必须符合 C++ 标识符规范"
        );
        assert_eq!(
            ValidationCode::InvalidFieldName("invalid-field".to_string()).to_string(),
            "字段名 'invalid-field' 无效，必须符合 C++ 标识符规范"
        );
        assert_eq!(
            ValidationCode::KeywordCollision("class".to_string()).to_string(),
            "字段名 'class' 是 C++ 保留关键字"
        );
        assert_eq!(
            ValidationCode::DuplicateFieldName("duplicate".to_string()).to_string(),
            "字段名 'duplicate' 重复定义"
        );
        assert_eq!(
            ValidationCode::InvalidCommandIdFormat("0xFFFFF".to_string()).to_string(),
            "Command ID '0xFFFFF' 格式错误，必须是 0-65535 的整数或十六进制"
        );

        // Test warning messages
        assert_eq!(
            ValidationCode::NamingConventionPacket("invalid_name".to_string()).to_string(),
            "Packet名称 'invalid_name' 建议使用大驼峰命名法 (PascalCase)"
        );
        assert_eq!(
            ValidationCode::NamingConventionField("InvalidField".to_string()).to_string(),
            "字段名 'InvalidField' 建议使用蛇形命名法 (snake_case)"
        );
        assert_eq!(
            ValidationCode::MissingComment("field_name".to_string()).to_string(),
            "建议为字段 'field_name' 添加注释"
        );
    }

    #[test]
    fn test_validation_code_equality() {
        let code1 = ValidationCode::InvalidPacketName("Test".to_string());
        let code2 = ValidationCode::InvalidPacketName("Test".to_string());
        let code3 = ValidationCode::InvalidFieldName("Test".to_string());

        assert_eq!(code1, code2);
        assert_ne!(code1, code3);
    }

    #[test]
    fn test_diagnostic_creation() {
        let error_diag = Diagnostic::error(
            ValidationCode::InvalidPacketName("BadName".to_string()),
            Some("packet_name".to_string()),
        );
        assert_eq!(error_diag.severity, Severity::Error);
        assert_eq!(
            error_diag.code,
            ValidationCode::InvalidPacketName("BadName".to_string())
        );
        assert_eq!(error_diag.field, Some("packet_name".to_string()));

        let warning_diag = Diagnostic::warning(
            ValidationCode::NamingConventionField("BadName".to_string()),
            Some("BadName".to_string()),
        );
        assert_eq!(warning_diag.severity, Severity::Warning);
        assert_eq!(
            warning_diag.code,
            ValidationCode::NamingConventionField("BadName".to_string())
        );
        assert_eq!(warning_diag.field, Some("BadName".to_string()));
    }

    #[test]
    fn test_diagnostic_without_field() {
        let diag = Diagnostic::error(
            ValidationCode::InvalidCommandIdFormat("invalid".to_string()),
            None,
        );
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(
            diag.code,
            ValidationCode::InvalidCommandIdFormat("invalid".to_string())
        );
        assert_eq!(diag.field, None);
    }

    #[test]
    fn test_diagnostic_clone() {
        let original = Diagnostic::error(
            ValidationCode::InvalidFieldName("test_field".to_string()),
            Some("test_field".to_string()),
        );
        let cloned = original.clone();

        assert_eq!(original.severity, cloned.severity);
        assert_eq!(original.code, cloned.code);
        assert_eq!(original.field, cloned.field);
    }
}
