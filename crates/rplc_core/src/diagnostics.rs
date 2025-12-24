use miette::Diagnostic;
use serde::Serialize;
use thiserror::Error;

pub type Span = (usize, usize);

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Error, Diagnostic, Serialize, PartialEq)]
pub enum ValidationCode {
    // ---- Errors ----
    #[error("Packet名称 '{0}' 无效，必须符合 C++ 标识符规范")]
    #[diagnostic(
        code(rplc::invalid_packet_name),
        help("Packet名称必须以字母或下划线开头，且只包含字母数字下划线")
    )]
    InvalidPacketName(String),

    #[error("字段名 '{0}' 无效，必须符合 C++ 标识符规范")]
    #[diagnostic(
        code(rplc::invalid_field_name),
        help("Field名称必须以字母或下划线开头，且只包含字母数字下划线")
    )]
    InvalidFieldName(String),

    #[error("字段名 '{0}' 是 C++ 保留关键字")]
    #[diagnostic(
        code(rplc::keyword_collision),
        help("请在该字段名后添加后缀，例如 '{0}_value'")
    )]
    KeywordCollision(String),

    #[error("字段名 '{0}' 重复定义")]
    #[diagnostic(code(rplc::duplicate_field))]
    DuplicateFieldName(String),

    #[error("Command ID '{0}' 格式错误，必须是 0-65535 的整数或十六进制")]
    #[diagnostic(
        code(rplc::invalid_cmd_id),
        help("ID 必须是 0-65535 的整数，或 0x 开头的十六进制")
    )]
    InvalidCommandId(String),

    #[error("'{0}' 的 Type 无效")]
    #[diagnostic(code(rplc::invalid_field_type), help("请为字段指定合法的C/C++类型"))]
    InvalidFieldType(String),

    #[error("'{0}' 的位域限定符无效")]
    #[diagnostic(code(rplc::bit_field::invalid), help("位域限定符应该是正整数"))]
    InvalidBitField(String),

    #[error("字段 '{0}' 在不允许的变量类型: '{0}' 上添加了位域限定符")]
    #[diagnostic(
        code(rplc::bit_field::invalid_type),
        help("位域字段必须是数字类型，不接受字符串、布尔值或其他类型")
    )]
    BitFieldOnInvalidType(String, String),

    #[error("字段 '{0}' 的位域限定符长度: {1} 超过了其类型本身的大小: {2}")]
    #[diagnostic(
        code(rplc::bit_field::length_overflow),
        help("位域限定符长度不能超过其类型本身")
    )]
    BitFieldLengthOverflow(String, u8, u8),

    #[error("位域字段 '{0}' 和 '{1}' 存在跨存储单元行为({2} + {3} > {4})，且内存布局非紧凑")]
    #[diagnostic(
        code(rplc::bit_field::straddle_boundary_without_packed),
        help("非紧凑情况下的跨储存单元位域没有意义，请去除位域定义或添加紧凑内存限定符")
    )]
    BitFieldStraddleBoundaryWithoutPacked(String, String, u8, u8, u8),

    // ---- Warnings ----
    #[error("Packet名称 '{0}' 建议使用大驼峰命名法 (PascalCase)")]
    #[diagnostic(
        severity(Warning),
        code(rplc::style::packet),
        help("建议 Packet 使用大驼峰命名 (PascalCase)")
    )]
    NamingConventionPacket(String),

    #[error("字段名 '{0}' 建议使用蛇形命名法 (snake_case)")]
    #[diagnostic(
        severity(Warning),
        code(rplc::style::field),
        help("建议 Field 使用蛇形命名法 (snake_case)")
    )]
    NamingConventionField(String),

    #[error("建议为字段 '{0}' 添加注释")]
    #[diagnostic(
        severity(Warning),
        code(rplc::doc::missing),
        help("添加注释有助于生成文档")
    )]
    MissingComment(String),

    #[error("'{0}' 字段使用位域的同时未启用紧凑结构体")]
    #[diagnostic(
        severity(Warning),
        code(rplc::bit_field::missing_packed_attr),
        help("使用紧凑结构体能消除位域成员之间的空白填充，避免占用额外空间，提高跨平台兼容性")
    )]
    BitFieldMissingPackedAttr(String),

    #[error("'{0} 字段位域跨越了存储单元边界")]
    #[diagnostic(
        severity(Warning),
        code(rplc::bit_field::straddle_boundary),
        help("位域跨越存储单元边界会增加CPU访问成员的开销")
    )]
    BitFieldStraddleBoundary(String),
}

#[derive(Debug, Clone, Error, Diagnostic, Serialize)]
#[error("{code}")]
pub struct RplcDiagnostic {
    #[source]
    #[diagnostic_source]
    pub code: ValidationCode,

    pub severity: Severity,
    pub span: Option<Span>,
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
            ValidationCode::InvalidCommandId("0xFFFFF".to_string()).to_string(),
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
    fn test_rplc_diagnostic_creation() {
        let error_diag = RplcDiagnostic {
            code: ValidationCode::InvalidPacketName("BadName".to_string()),
            severity: Severity::Error,
            span: None,
        };
        assert_eq!(error_diag.severity, Severity::Error);
        assert_eq!(
            error_diag.code,
            ValidationCode::InvalidPacketName("BadName".to_string())
        );

        let warning_diag = RplcDiagnostic {
            code: ValidationCode::NamingConventionField("BadName".to_string()),
            severity: Severity::Warning,
            span: Some((0, 10)),
        };
        assert_eq!(warning_diag.severity, Severity::Warning);
        assert_eq!(
            warning_diag.code,
            ValidationCode::NamingConventionField("BadName".to_string())
        );
    }

    #[test]
    fn test_rplc_diagnostic_clone() {
        let original = RplcDiagnostic {
            code: ValidationCode::InvalidFieldName("test_field".to_string()),
            severity: Severity::Error,
            span: Some((5, 15)),
        };
        let cloned = original.clone();

        assert_eq!(original.severity, cloned.severity);
        assert_eq!(original.code, cloned.code);
        assert_eq!(original.span, cloned.span);
    }

    #[test]
    fn test_validation_code_bit_field_error_messages() {
        // Test bit field error messages
        assert_eq!(
            ValidationCode::InvalidBitField("field_name".to_string()).to_string(),
            "'field_name' 的位域限定符无效"
        );
        assert_eq!(
            ValidationCode::BitFieldOnInvalidType("field_name".to_string(), "float".to_string()).to_string(),
            "字段 'field_name' 在不允许的变量类型: 'field_name' 上添加了位域限定符"
        );
        assert_eq!(
            ValidationCode::BitFieldLengthOverflow("field_name".to_string(), 10, 8).to_string(),
            "字段 'field_name' 的位域限定符长度: 10 超过了其类型本身的大小: 8"
        );
        assert_eq!(
            ValidationCode::BitFieldStraddleBoundaryWithoutPacked("field1".to_string(), "field2".to_string(), 5, 6, 8).to_string(),
            "位域字段 'field1' 和 'field2' 存在跨存储单元行为(5 + 6 > 8)，且内存布局非紧凑"
        );

        // Test bit field warning messages
        assert_eq!(
            ValidationCode::BitFieldMissingPackedAttr("field_name".to_string()).to_string(),
            "'field_name' 字段使用位域的同时未启用紧凑结构体"
        );
        assert_eq!(
            ValidationCode::BitFieldStraddleBoundary("field_name".to_string()).to_string(),
            "'field_name 字段位域跨越了存储单元边界"
        );
    }

    #[test]
    fn test_validation_code_bit_field_equality() {
        let code1 = ValidationCode::InvalidBitField("test_field".to_string());
        let code2 = ValidationCode::InvalidBitField("test_field".to_string());
        let code3 = ValidationCode::InvalidBitField("other_field".to_string());
        let code4 = ValidationCode::BitFieldOnInvalidType("field".to_string(), "type".to_string());

        assert_eq!(code1, code2);
        assert_ne!(code1, code3);
        assert_ne!(code1, code4);
    }

    #[test]
    fn test_rplc_diagnostic_with_bit_field_codes() {
        let error_diag = RplcDiagnostic {
            code: ValidationCode::InvalidBitField("bad_field".to_string()),
            severity: Severity::Error,
            span: None,
        };
        assert_eq!(error_diag.severity, Severity::Error);
        assert_eq!(
            error_diag.code,
            ValidationCode::InvalidBitField("bad_field".to_string())
        );

        let warning_diag = RplcDiagnostic {
            code: ValidationCode::BitFieldMissingPackedAttr("warn_field".to_string()),
            severity: Severity::Warning,
            span: Some((10, 20)),
        };
        assert_eq!(warning_diag.severity, Severity::Warning);
        assert_eq!(
            warning_diag.code,
            ValidationCode::BitFieldMissingPackedAttr("warn_field".to_string())
        );
    }
}
