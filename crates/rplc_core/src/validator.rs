use json_spanned_value as jsv;
use regex::Regex;
use std::collections::HashSet;

use crate::diagnostics::{RplcDiagnostic, Severity, ValidationCode};

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

pub fn validate(json_input: &str) -> Vec<RplcDiagnostic> {
    let mut diags = Vec::new();
    let identifier_re = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();

    let root: jsv::Value = match jsv::from_str(json_input) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let mut add_diag = |severity: Severity, code, span_node: &jsv::Spanned<jsv::Value>| {
        let span = span_node.span();
        diags.push(RplcDiagnostic {
            code,
            severity, // 使用传入的参数
            span: Some((span.0, span.1 - span.0)),
        });
    };

    if let jsv::Value::Object(map) = root {
        // Packet name
        if let Some(name_node) = map.get("packet_name") {
            if let Some(name) = name_node.as_string() {
                if !identifier_re.is_match(name) {
                    add_diag(
                        Severity::Error,
                        ValidationCode::InvalidPacketName(name.to_string()),
                        name_node,
                    );
                } else if name
                    .chars()
                    .next()
                    .map(|c| c.is_lowercase())
                    .unwrap_or(false)
                {
                    add_diag(
                        Severity::Warning,
                        ValidationCode::NamingConventionPacket(name.to_string()),
                        name_node,
                    );
                }
            }
        }

        // Command ID
        if let Some(id_node) = map.get("command_id") {
            if let Some(id_str) = id_node.as_string() {
                if crate::validator::parse_command_id(id_str).is_err() {
                    add_diag(
                        Severity::Error,
                        ValidationCode::InvalidCommandId(id_str.to_string()),
                        id_node,
                    );
                }
            }
        }

        // Packed
        let mut is_packed = map.get("packed").and_then(|n| n.as_bool()).unwrap_or(true);

        // Fields
        if let Some(field_nodes) = map.get("fields") {
            let fields = field_nodes.as_array().unwrap();
            let mut seen_fields = HashSet::new();

            // 存储位域信息用于后续检查
            let mut bitfield_info: Vec<(String, String, u8, u8)> = Vec::new(); // (field_name, field_type, type_bits, bitfield_bits)

            for field_node in fields {
                let mut field_name: String = "".to_string();

                if let Some(field_map) = field_node.as_object() {
                    if let Some(name_node) = field_map.get("name") {
                        if let Some(name) = name_node.as_string() {
                            // Format
                            if !identifier_re.is_match(name) {
                                add_diag(
                                    Severity::Error,
                                    ValidationCode::InvalidFieldName(name.to_string()),
                                    name_node,
                                );
                            }

                            // Keyword
                            if is_cpp_keyword(name) {
                                add_diag(
                                    Severity::Error,
                                    ValidationCode::KeywordCollision(name.to_string()),
                                    name_node,
                                );
                            }

                            // Repeat
                            if !seen_fields.insert(name.to_string()) {
                                add_diag(
                                    Severity::Error,
                                    ValidationCode::DuplicateFieldName(name.to_string()),
                                    name_node,
                                );
                            }
                            field_name = name.to_string();
                        }
                    }
                    // Type
                    let mut ty: Option<&str> = None;
                    if let Some(ty_node) = field_map.get("type") {
                        if let Some(ty_str) = ty_node.as_string() {
                            ty = Some(ty_str);
                        } else {
                            add_diag(
                                Severity::Error,
                                ValidationCode::InvalidFieldType(field_name.clone()),
                                ty_node,
                            )
                        }
                    } else {
                        add_diag(
                            Severity::Error,
                            ValidationCode::InvalidFieldType(field_name.clone()),
                            field_node,
                        )
                    }

                    // Bit-Field
                    let has_bitfield = if let Some(bitfield_node) = field_map.get("bitfield") {
                        // 检查位域值是否为数字
                        if let Some(bitfield_num) = bitfield_node.as_number() {
                            // 检查位域值是否为整数
                            if !bitfield_num.is_i64() {
                                add_diag(
                                    Severity::Error,
                                    ValidationCode::InvalidBitField(field_name.clone()),
                                    bitfield_node,
                                );
                                false
                            } else if let Some(bitfield_value) = bitfield_num.as_i64() {
                                // 检查位域值是否为正数
                                if bitfield_value <= 0 {
                                    add_diag(
                                        Severity::Error,
                                        ValidationCode::InvalidBitField(field_name.clone()),
                                        bitfield_node,
                                    );
                                    false
                                } else {
                                    // 检查类型是否支持位域
                                    if let Some(field_type) = ty {
                                        let type_size = c_type_to_bitfield_size(field_type);
                                        if type_size.is_none() {
                                            add_diag(
                                                Severity::Error,
                                                ValidationCode::BitFieldOnInvalidType(
                                                    field_name.clone(),
                                                    field_type.to_string(),
                                                ),
                                                bitfield_node,
                                            );
                                            false
                                        } else {
                                            // 检查位域长度是否超过类型本身的大小
                                            let type_bits = type_size.unwrap() * 8;
                                            let bitfield_value_u8 = bitfield_value as u8;
                                            if bitfield_value_u8 > type_bits {
                                                add_diag(
                                                    Severity::Error,
                                                    ValidationCode::BitFieldLengthOverflow(
                                                        field_name.clone(),
                                                        bitfield_value_u8,
                                                        type_bits,
                                                    ),
                                                    bitfield_node,
                                                );
                                                false
                                            } else {
                                                // 记录位域信息用于后续检查
                                                bitfield_info.push((
                                                    field_name.clone(),
                                                    field_type.to_string(),
                                                    type_bits,
                                                    bitfield_value_u8,
                                                ));
                                                true // 有效的位域
                                            }
                                        }
                                    } else {
                                        add_diag(
                                            Severity::Error,
                                            ValidationCode::InvalidFieldType(field_name.clone()),
                                            field_node,
                                        );
                                        false
                                    }
                                }
                            } else {
                                add_diag(
                                    Severity::Error,
                                    ValidationCode::InvalidBitField(field_name.clone()),
                                    bitfield_node,
                                );
                                false
                            }
                        } else {
                            add_diag(
                                Severity::Error,
                                ValidationCode::InvalidBitField(field_name.clone()),
                                bitfield_node,
                            );
                            false
                        }
                    } else {
                        false
                    };

                    if has_bitfield && !is_packed {
                        add_diag(
                            Severity::Warning,
                            ValidationCode::BitFieldMissingPackedAttr(field_name.clone()),
                            field_node,
                        );
                    }

                    // Comment
                    let has_comment = field_map
                        .get("comment")
                        .and_then(|c| c.as_string())
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false);

                    if !has_comment {
                        let target_node = field_map.get("name").unwrap_or(field_node);
                        let field_name = field_map
                            .get("name")
                            .and_then(|n| n.as_string())
                            .unwrap_or("unknown");
                        add_diag(
                            Severity::Warning,
                            ValidationCode::MissingComment(field_name.to_string()),
                            target_node,
                        );
                    }
                }
            }

            // 检查跨存储单元边界的位域
            if !is_packed && bitfield_info.len() > 1 {
                for i in 1..bitfield_info.len() {
                    let (prev_field_name, _prev_field_type, _prev_type_bits, prev_bitfield_bits) =
                        &bitfield_info[i - 1];
                    let (field_name, _field_type, type_bits, bitfield_bits) = &bitfield_info[i];

                    // 如果前一个位域和当前位域的总和超过类型位数，则存在跨边界问题
                    if prev_bitfield_bits + bitfield_bits > *type_bits {
                        add_diag(
                            Severity::Error,
                            ValidationCode::BitFieldStraddleBoundaryWithoutPacked(
                                prev_field_name.clone(),
                                field_name.clone(),
                                *prev_bitfield_bits,
                                *bitfield_bits,
                                *type_bits,
                            ),
                            field_nodes, // 使用整个fields数组作为节点
                        );
                    }
                }
            }

            // 检查单个位域是否跨越边界
            for (field_name, field_type, type_bits, bitfield_bits) in &bitfield_info {
                if *bitfield_bits == *type_bits && !is_packed {
                    add_diag(
                        Severity::Warning,
                        ValidationCode::BitFieldStraddleBoundary(field_name.clone()),
                        field_nodes, // 使用整个fields数组作为节点
                    );
                }
            }
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

pub fn is_cpp_keyword(name: &str) -> bool {
    CPP_KEYWORDS.contains(&name)
}

pub fn c_type_to_bitfield_size(ty: &str) -> Option<u8> {
    match ty {
        "unsigned int" | "signed int" | "int" => Some(4),
        "_Bool" | "bool" => Some(1),

        "unsigned char" | "signed char" | "char" => Some(1),
        "unsigned short" | "signed short" | "short" => Some(2),
        "unsigned long" | "signed long" | "long" => Some(8),
        "unsigned long long" | "signed long long" | "long long" => Some(8),

        "uint8_t" | "int8_t" => Some(1),
        "uint16_t" | "int16_t" => Some(2),
        "uint32_t" | "int32_t" => Some(4),
        "uint64_t" | "int64_t" => Some(8),

        "float" | "double" | "long double" => None,
        "void*" | "char*" | "int*" => None,
        "struct" | "union" => None,

        _ => None,
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
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "valid_field",
                    "type": "uint8_t",
                    "comment": "A valid field"
                },
                {
                    "name": "another_field",
                    "type": "float",
                    "comment": "Another valid field"
                }
            ]
        }"#;

        let diags = validate(json);
        assert!(diags.is_empty()); // Should have no diagnostics
    }

    #[test]
    fn test_validate_invalid_packet_name() {
        let json = r#"{
            "packet_name": "invalid-packet-name",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": []
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have error only (not a valid identifier to check naming convention)
        assert!(matches!(
            diags[0].code,
            ValidationCode::InvalidPacketName(_)
        ));
        assert_eq!(diags[0].severity, Severity::Error);
    }

    #[test]
    fn test_validate_lowercase_packet_name_warning() {
        let json = r#"{
            "packet_name": "lowercase_packet",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": []
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have naming convention warning
        assert!(matches!(
            diags[0].code,
            ValidationCode::NamingConventionPacket(_)
        ));
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    #[test]
    fn test_validate_invalid_command_id() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "invalid-id",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": []
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have command ID error
        assert!(matches!(diags[0].code, ValidationCode::InvalidCommandId(_)));
        assert_eq!(diags[0].severity, Severity::Error);
    }

    #[test]
    fn test_validate_invalid_field_name() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "invalid-field",
                    "type": "uint8_t",
                    "comment": "Invalid field"
                }
            ]
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have field name error
        assert!(matches!(diags[0].code, ValidationCode::InvalidFieldName(_)));
        assert_eq!(diags[0].severity, Severity::Error);
    }

    #[test]
    fn test_validate_keyword_collision() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "class",
                    "type": "uint8_t",
                    "comment": "Class field"
                }
            ]
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have keyword collision error only (comment is present)
        assert!(matches!(diags[0].code, ValidationCode::KeywordCollision(_)));
        assert_eq!(diags[0].severity, Severity::Error);
    }

    #[test]
    fn test_validate_duplicate_field_names() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "duplicate_field",
                    "type": "uint8_t",
                    "comment": "First field"
                },
                {
                    "name": "duplicate_field",
                    "type": "float",
                    "comment": "Second field"
                }
            ]
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have duplicate field error (only for the second occurrence)
        assert!(matches!(
            diags[0].code,
            ValidationCode::DuplicateFieldName(_)
        ));
        assert_eq!(diags[0].severity, Severity::Error);
    }

    #[test]
    fn test_validate_missing_comment_warning() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "field_without_comment",
                    "type": "uint8_t",
                    "comment": null
                }
            ]
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have missing comment warning
        assert!(matches!(diags[0].code, ValidationCode::MissingComment(_)));
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    #[test]
    fn test_validate_empty_comment_warning() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "field_with_empty_comment",
                    "type": "uint8_t",
                    "comment": ""
                }
            ]
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have missing comment warning
        assert!(matches!(diags[0].code, ValidationCode::MissingComment(_)));
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    #[test]
    fn test_validate_whitespace_only_comment_warning() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "field_with_whitespace_comment",
                    "type": "uint8_t",
                    "comment": "   \t\n  "
                }
            ]
        }"#;

        let diags = validate(json);
        assert_eq!(diags.len(), 1); // Should have missing comment warning
        assert!(matches!(diags[0].code, ValidationCode::MissingComment(_)));
        assert_eq!(diags[0].severity, Severity::Warning);
    }
}
