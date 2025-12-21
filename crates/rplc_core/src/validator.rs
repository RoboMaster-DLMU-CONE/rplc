use std::collections::HashSet;

use regex::Regex;

use crate::{
    config::{Config, Field},
    diagnostics::{Diagnostic, ValidationCode},
};

const CPP_KEYWORDS: &[&str] = &[
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "atomic_cancel",
    "atomic_commit",
    "atomic_noexcept",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char8_t",
    "char16_t",
    "char32_t",
    "class",
    "compl",
    "concept",
    "const",
    "consteval",
    "constexpr",
    "constinit",
    "const_cast",
    "continue",
    "contract_assert",
    "co_await",
    "co_return",
    "co_yield",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "reflexpr",
    "register",
    "reinterpret_cast",
    "requires",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "synchronized",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
];

pub fn validate(config: &Config) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    let identifier_re = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();

    // Packet name
    if !identifier_re.is_match(&config.packet_name) {
        diags.push(Diagnostic::error(
            ValidationCode::InvalidPacketName(config.packet_name.clone()),
            Some("packet_name".to_string()),
        ));
    } else if config
        .packet_name
        .chars()
        .next()
        .map(|c| c.is_lowercase())
        .unwrap_or(false)
    {
        diags.push(Diagnostic::warning(
            ValidationCode::NamingConventionPacket(config.packet_name.clone()),
            Some("packet_name".to_string()),
        ))
    }
    // Command ID
    if parse_command_id(&config.command_id).is_err() {
        diags.push(Diagnostic::error(
            ValidationCode::InvalidCommandIdFormat(config.command_id.clone()),
            Some("command_id".to_string()),
        ));
    }
    // Field
    let mut seen_fields = HashSet::new();
    for field in &config.fields {
        // format
        if !identifier_re.is_match(&field.name) {
            diags.push(Diagnostic::error(
                ValidationCode::InvalidFieldName(field.name.clone()),
                Some(field.name.clone()),
            ));
        }
        // keyword
        if CPP_KEYWORDS.contains(&field.name.as_str()) {
            diags.push(Diagnostic::error(
                ValidationCode::KeywordCollision(field.name.clone()),
                Some(field.name.clone()),
            ));
        }
        // repeat
        if !seen_fields.insert(&field.name) {
            diags.push(Diagnostic::error(
                ValidationCode::DuplicateFieldName(field.name.clone()),
                Some(field.name.clone()),
            ));
        }
        // comment
        if field.comment.is_none() || field.comment.as_ref().unwrap().trim().is_empty() {
            diags.push(Diagnostic::warning(
                ValidationCode::MissingComment(field.name.clone()),
                Some(field.name.clone()),
            ));
        }
    }

    diags
}

pub fn parse_command_id(id: &str) -> Result<u16, ()> {
    let clean = id.trim();
    if clean.to_lowercase().starts_with("0x") {
        u16::from_str_radix(&clean[2..], 16).map_err(|_| ())
    } else {
        clean.parse::<u16>().map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::Severity;

    #[test]
    fn test_parse_command_id_hex_valid() {
        assert_eq!(parse_command_id("0x0104"), Ok(260)); // 0x0104 = 260 decimal
        assert_eq!(parse_command_id("0xABCD"), Ok(43981)); // 0xABCD = 43981 decimal
        assert_eq!(parse_command_id("0xffff"), Ok(65535)); // Maximum 16-bit value
        assert_eq!(parse_command_id("0x0"), Ok(0)); // Minimum hex value
    }

    #[test]
    fn test_parse_command_id_decimal_valid() {
        assert_eq!(parse_command_id("260"), Ok(260));
        assert_eq!(parse_command_id("65535"), Ok(65535)); // Maximum 16-bit value
        assert_eq!(parse_command_id("0"), Ok(0)); // Minimum decimal value
    }

    #[test]
    fn test_parse_command_id_invalid_formats() {
        // Test invalid hex values
        assert!(parse_command_id("0xGHIJ").is_err()); // Invalid hex digits
        assert!(parse_command_id("0x12345").is_err()); // More than 4 hex digits (exceeds 16-bit range)
        assert!(parse_command_id("0xFFFFFFFF").is_err()); // Much bigger than 16-bit

        // Test invalid decimal values
        assert!(parse_command_id("65536").is_err()); // Exceeds 16-bit range
        assert!(parse_command_id("invalid").is_err()); // Non-numeric
        assert!(parse_command_id("").is_err()); // Empty string
        assert!(parse_command_id("  ").is_err()); // Whitespace only
    }

    #[test]
    fn test_parse_command_id_case_insensitive_hex() {
        assert_eq!(parse_command_id("0xABCD"), Ok(43981));
        assert_eq!(parse_command_id("0xabcd"), Ok(43981));
        assert_eq!(parse_command_id("0xAbCd"), Ok(43981));
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config {
            packet_name: "ValidPacket".to_string(), // Valid PascalCase name
            command_id: "0x0104".to_string(),       // Valid command ID
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![
                Field {
                    name: "valid_field".to_string(), // Valid snake_case name
                    ty: "uint8_t".to_string(),
                    comment: Some("A valid field".to_string()), // Has comment
                },
                Field {
                    name: "another_field".to_string(), // Valid snake_case name
                    ty: "float".to_string(),
                    comment: Some("Another valid field".to_string()), // Has comment
                },
            ],
        };

        let diags = validate(&config);
        assert!(diags.is_empty()); // Should have no diagnostics
    }

    #[test]
    fn test_validate_invalid_packet_name() {
        let config = Config {
            packet_name: "invalid-packet-name".to_string(), // Contains hyphens
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have error only (not a valid identifier to check naming convention)
        assert!(matches!(
            diags[0].code,
            ValidationCode::InvalidPacketName(_)
        ));
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].field, Some("packet_name".to_string()));
    }

    #[test]
    fn test_validate_lowercase_packet_name_warning() {
        let config = Config {
            packet_name: "lowercase_packet".to_string(), // Lowercase - should warn
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have naming convention warning
        assert!(matches!(
            diags[0].code,
            ValidationCode::NamingConventionPacket(_)
        ));
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    #[test]
    fn test_validate_invalid_command_id() {
        let config = Config {
            packet_name: "ValidPacket".to_string(),
            command_id: "invalid-id".to_string(), // Invalid format
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have command ID error
        assert!(matches!(
            diags[0].code,
            ValidationCode::InvalidCommandIdFormat(_)
        ));
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].field, Some("command_id".to_string()));
    }

    #[test]
    fn test_validate_invalid_field_name() {
        let config = Config {
            packet_name: "ValidPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![Field {
                name: "invalid-field".to_string(), // Contains hyphen
                ty: "uint8_t".to_string(),
                comment: Some("Invalid field".to_string()),
            }],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have field name error
        assert!(matches!(diags[0].code, ValidationCode::InvalidFieldName(_)));
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].field, Some("invalid-field".to_string()));
    }

    #[test]
    fn test_validate_keyword_collision() {
        let config = Config {
            packet_name: "ValidPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![Field {
                name: "class".to_string(), // C++ keyword
                ty: "uint8_t".to_string(),
                comment: Some("Class field".to_string()),
            }],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have keyword collision error only (comment is present)
        assert!(matches!(diags[0].code, ValidationCode::KeywordCollision(_)));
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].field, Some("class".to_string()));
    }

    #[test]
    fn test_validate_duplicate_field_names() {
        let config = Config {
            packet_name: "ValidPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![
                Field {
                    name: "duplicate_field".to_string(),
                    ty: "uint8_t".to_string(),
                    comment: Some("First field".to_string()),
                },
                Field {
                    name: "duplicate_field".to_string(), // Duplicate name
                    ty: "float".to_string(),
                    comment: Some("Second field".to_string()),
                },
            ],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have duplicate field error (only for the second occurrence)
        assert!(matches!(
            diags[0].code,
            ValidationCode::DuplicateFieldName(_)
        ));
        assert_eq!(diags[0].severity, Severity::Error);
        assert_eq!(diags[0].field, Some("duplicate_field".to_string()));
    }

    #[test]
    fn test_validate_missing_comment_warning() {
        let config = Config {
            packet_name: "ValidPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![Field {
                name: "field_without_comment".to_string(),
                ty: "uint8_t".to_string(),
                comment: None, // Missing comment
            }],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have missing comment warning
        assert!(matches!(diags[0].code, ValidationCode::MissingComment(_)));
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].field, Some("field_without_comment".to_string()));
    }

    #[test]
    fn test_validate_empty_comment_warning() {
        let config = Config {
            packet_name: "ValidPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![Field {
                name: "field_with_empty_comment".to_string(),
                ty: "uint8_t".to_string(),
                comment: Some("".to_string()), // Empty comment
            }],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have missing comment warning
        assert!(matches!(diags[0].code, ValidationCode::MissingComment(_)));
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].field, Some("field_with_empty_comment".to_string()));
    }

    #[test]
    fn test_validate_whitespace_only_comment_warning() {
        let config = Config {
            packet_name: "ValidPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: None,
            fields: vec![Field {
                name: "field_with_whitespace_comment".to_string(),
                ty: "uint8_t".to_string(),
                comment: Some("   \t\n  ".to_string()), // Whitespace only comment
            }],
        };

        let diags = validate(&config);
        assert_eq!(diags.len(), 1); // Should have missing comment warning
        assert!(matches!(diags[0].code, ValidationCode::MissingComment(_)));
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(
            diags[0].field,
            Some("field_with_whitespace_comment".to_string())
        );
    }
}
