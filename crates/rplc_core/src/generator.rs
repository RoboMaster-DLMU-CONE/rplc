use crate::config::Config;
use crate::diagnostics::Severity;
use crate::validator::{parse_command_id, validate};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("JSON解析失败: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("配置验证未通过，请检查错误信息")]
    ValidationError,
}

pub fn generate(json_input: &str) -> Result<String, GenerateError> {
    let config: Config = serde_json::from_str(json_input)?;
    let diags = validate(json_input);
    for diag in diags {
        if diag.severity == Severity::Error {
            return Err(GenerateError::ValidationError);
        }
    }
    let cmd_id = parse_command_id(&config.command_id).unwrap();
    let guard = config
        .header_guard
        .clone()
        .unwrap_or_else(|| format!("RPL_{}_HPP", config.packet_name.to_uppercase()));

    let mut out = String::new();
    // Header Guard
    out.push_str(&format!("#ifndef {}\n", guard));
    out.push_str(&format!("#define {}\n\n", guard));

    // Includes
    out.push_str("#include <cstdint>\n");
    out.push_str("#include <RPL/Meta/PacketTraits.hpp>\n\n");

    // Namespace
    if let Some(ns) = &config.namespace {
        out.push_str(&format!("namespace {} {{\n\n", ns));
    }

    let packed = if config.packed {
        "__attribute__((packed)) "
    } else {
        ""
    };
    out.push_str(&format!("struct {}{}\n{{\n", packed, config.packet_name));

    // Fields
    for field in &config.fields {
        out.push_str(&format!("    {} {}", field.ty, field.name));
        if let Some(bf) = field.bit_field {
            out.push_str(&format!(" : {};", bf));
        } else {
            out.push(';');
        }
        if let Some(cmt) = &field.comment {
            out.push_str(&format!(" // {}", cmt));
        }
        out.push('\n');
    }
    out.push_str("};\n\n");

    // Traits
    out.push_str("template <>\n");
    out.push_str(&format!(
        "struct RPL::Meta::PacketTraits<{}> : PacketTraitsBase<PacketTraits<{}>>\n",
        config.packet_name, config.packet_name
    ));
    out.push_str("{\n");
    out.push_str(&format!(
        "    static constexpr uint16_t cmd = 0x{:04X};\n",
        cmd_id
    ));
    out.push_str(&format!(
        "    static constexpr size_t size = sizeof({});\n",
        config.packet_name
    ));
    out.push_str("};\n");

    // End Namespace
    if let Some(ns) = &config.namespace {
        out.push_str(&format!("}} // namespace {}\n\n", ns));
    }

    out.push_str(&format!("#endif // {}\n", guard));
    Ok(out)
}

// New functionality to support generating multiple packets
#[derive(Debug, Error)]
pub enum MultiGenerateError {
    #[error("JSON解析失败: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("配置验证未通过，请检查错误信息")]
    ValidationError,
    #[error("代码生成失败: {0}")]
    GenerateError(#[from] GenerateError),
}

pub fn generate_multiple(json_input: &str) -> Result<Vec<(String, String)>, MultiGenerateError> {
    // Try to parse as a single config first (for backward compatibility)
    if let Ok(single_config) = serde_json::from_str::<Config>(json_input) {
        let diags = validate(json_input);
        for diag in diags {
            if diag.severity == Severity::Error {
                return Err(MultiGenerateError::ValidationError);
            }
        }
        let output = generate(json_input)?;
        return Ok(vec![(single_config.packet_name, output)]);
    }

    // If single config parsing fails, try to parse as an array of configs
    let configs: Vec<Config> = serde_json::from_str(json_input)?;
    let mut results = Vec::new();

    for config in configs {
        // Create JSON for each individual config to validate
        let config_json = serde_json::to_string(&config)?;
        let diags = validate(&config_json);
        for diag in diags {
            if diag.severity == Severity::Error {
                return Err(MultiGenerateError::ValidationError);
            }
        }

        // Generate output for this config
        let output = generate(&config_json)?;
        results.push((config.packet_name, output));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_basic_packet() {
        let json = r#"{
            "packet_name": "BasicPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_BASICPACKET_HPP",
            "fields": [
                {
                    "name": "field1",
                    "type": "uint8_t",
                    "comment": "First field"
                },
                {
                    "name": "field2",
                    "type": "float",
                    "comment": "Second field"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("#ifndef RPL_BASICPACKET_HPP"));
        assert!(result.contains("#define RPL_BASICPACKET_HPP"));
        assert!(result.contains("__attribute__((packed)) BasicPacket"));
        assert!(result.contains("uint8_t field1; // First field"));
        assert!(result.contains("float field2; // Second field"));
        assert!(result.contains("static constexpr uint16_t cmd = 0x0104;"));
        assert!(result.contains("static constexpr size_t size = sizeof(BasicPacket)"));
        assert!(result.contains("#endif // RPL_BASICPACKET_HPP"));
    }

    #[test]
    fn test_generate_with_namespace() {
        let json = r#"{
            "packet_name": "NamespacePacket",
            "command_id": "0xABCD",
            "namespace": "Robot::Sensors",
            "packed": true,
            "header_guard": "RPL_NAMESPACEPACKET_HPP",
            "fields": [
                {
                    "name": "sensor_id",
                    "type": "uint16_t",
                    "comment": "Sensor identifier"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("namespace Robot::Sensors {"));
        assert!(result.contains("__attribute__((packed)) NamespacePacket"));
        assert!(result.contains("uint16_t sensor_id; // Sensor identifier"));
        assert!(result.contains("// namespace Robot::Sensors"));
        assert!(result.contains("static constexpr uint16_t cmd = 0xABCD;"));
    }

    #[test]
    fn test_generate_unpacked_packet() {
        let json = r#"{
            "packet_name": "UnpackedPacket",
            "command_id": "0x0201",
            "namespace": null,
            "packed": false,
            "header_guard": null,
            "fields": [
                {
                    "name": "data",
                    "type": "int32_t",
                    "comment": "Some data"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        // Should NOT contain packed attribute
        assert!(!result.contains("__attribute__((packed))"));
        assert!(result.contains("struct UnpackedPacket"));
        assert!(result.contains("int32_t data; // Some data"));
        assert!(result.contains("#ifndef RPL_UNPACKEDPACKET_HPP")); // Generated header guard
    }

    #[test]
    fn test_generate_with_default_header_guard() {
        let json = r#"{
            "packet_name": "DefaultGuardPacket",
            "command_id": "0x1234",
            "namespace": null,
            "packed": true,
            "header_guard": null,
            "fields": [
                {
                    "name": "value",
                    "type": "double",
                    "comment": "A double value"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        // Should generate default header guard based on packet name
        assert!(result.contains("#ifndef RPL_DEFAULTGUARDPACKET_HPP"));
        assert!(result.contains("#define RPL_DEFAULTGUARDPACKET_HPP"));
        assert!(result.contains("double value; // A double value"));
    }

    #[test]
    fn test_generate_with_field_without_comment() {
        let json = r#"{
            "packet_name": "NoCommentPacket",
            "command_id": "0x0101",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_NOCOMMENTPACKET_HPP",
            "fields": [
                {
                    "name": "no_comment_field",
                    "type": "uint32_t",
                    "comment": null
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("#ifndef RPL_NOCOMMENTPACKET_HPP"));
        assert!(result.contains("uint32_t no_comment_field;")); // No comment present
        // The trait comment lines will still be present, just not field comments
        // Let's check specifically for field comments
        assert!(!result.contains("uint32_t no_comment_field; //")); // No field comment
    }

    #[test]
    fn test_generate_validates_config() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "invalid-command-id",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_VALIDPACKET_HPP",
            "fields": [
                {
                    "name": "valid_field",
                    "type": "uint8_t",
                    "comment": "A field"
                }
            ]
        }"#;

        // This should fail validation due to invalid command ID
        let result = generate(json);
        assert!(result.is_err());
        match result.unwrap_err() {
            GenerateError::ValidationError => (), // Expected
            err => panic!("Expected ValidationError, but got: {:?}", err),
        }
    }

    #[test]
    fn test_generate_invalid_json() {
        let invalid_json = r#"{
            "packet_name": "InvalidJsonPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_INVALIDJSONPACKET_HPP",
            "fields": [
                {
                    "name": "field",
                    "type": "uint8_t",
                    "comment": "A field"
        }"#; // Malformed JSON

        let result = generate(invalid_json);
        assert!(result.is_err());

        match result.unwrap_err() {
            GenerateError::JsonError(_) => (), // Expected
            _ => panic!("Expected JsonError"),
        }
    }

    #[test]
    fn test_generate_invalid_command_id() {
        let json = r#"{
            "packet_name": "ValidPacket",
            "command_id": "invalid-command-id",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_VALIDPACKET_HPP",
            "fields": [
                {
                    "name": "field",
                    "type": "uint8_t",
                    "comment": "A field"
                }
            ]
        }"#;

        // This should fail validation due to invalid command ID
        let result = generate(json);
        assert!(result.is_err());
        match result.unwrap_err() {
            GenerateError::ValidationError => (), // Expected
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_generate_with_bit_fields() {
        let json = r#"{
            "packet_name": "BitFieldPacket",
            "command_id": "0x0105",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_BITFIELDPACKET_HPP",
            "fields": [
                {
                    "name": "status",
                    "type": "uint8_t",
                    "bit_field": 4,
                    "comment": "Status field"
                },
                {
                    "name": "flag",
                    "type": "uint8_t",
                    "bit_field": 3,
                    "comment": "Flag field"
                },
                {
                    "name": "reserved",
                    "type": "uint8_t",
                    "bit_field": 1,
                    "comment": "Reserved bit"
                },
                {
                    "name": "normal_field",
                    "type": "uint16_t",
                    "comment": "Normal field without bit field"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("#ifndef RPL_BITFIELDPACKET_HPP"));
        assert!(result.contains("__attribute__((packed)) BitFieldPacket"));
        assert!(result.contains("uint8_t status : 4; // Status field"));
        assert!(result.contains("uint8_t flag : 3; // Flag field"));
        assert!(result.contains("uint8_t reserved : 1; // Reserved bit"));
        assert!(result.contains("uint16_t normal_field; // Normal field without bit field"));
        assert!(result.contains("static constexpr uint16_t cmd = 0x0105;"));
    }

    #[test]
    fn test_generate_with_mixed_fields_and_bit_fields() {
        let json = r#"{
            "packet_name": "MixedFieldsPacket",
            "command_id": "0x0205",
            "namespace": "Robot::Controls",
            "packed": false,
            "header_guard": "RPL_MIXEDFIELDSPACKET_HPP",
            "fields": [
                {
                    "name": "cmd_type",
                    "type": "uint8_t",
                    "bit_field": 6,
                    "comment": "Command type"
                },
                {
                    "name": "priority",
                    "type": "uint8_t",
                    "bit_field": 2,
                    "comment": "Priority level"
                },
                {
                    "name": "data",
                    "type": "uint32_t",
                    "comment": "Data payload"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("namespace Robot::Controls {"));
        assert!(!result.contains("__attribute__((packed))")); // packed is false
        assert!(result.contains("uint8_t cmd_type : 6; // Command type"));
        assert!(result.contains("uint8_t priority : 2; // Priority level"));
        assert!(result.contains("uint32_t data; // Data payload"));
        assert!(result.contains("// namespace Robot::Controls"));
        assert!(result.contains("static constexpr uint16_t cmd = 0x0205;"));
    }

    #[test]
    fn test_generate_with_bit_fields_without_comments() {
        let json = r#"{
            "packet_name": "BitFieldsNoComments",
            "command_id": "0x0305",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_BITFIELDSNOCOMMENTS_HPP",
            "fields": [
                {
                    "name": "field1",
                    "type": "uint16_t",
                    "bit_field": 8
                },
                {
                    "name": "field2",
                    "type": "uint16_t",
                    "bit_field": 7
                },
                {
                    "name": "field3",
                    "type": "uint16_t",
                    "bit_field": 1
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("#ifndef RPL_BITFIELDSNOCOMMENTS_HPP"));
        assert!(result.contains("__attribute__((packed)) BitFieldsNoComments"));
        assert!(result.contains("uint16_t field1 : 8;"));
        assert!(result.contains("uint16_t field2 : 7;"));
        assert!(result.contains("uint16_t field3 : 1;"));
        // Ensure there are no trailing comments or malformed lines
        assert!(!result.contains(" : 8; //"));
        assert!(!result.contains(" : 7; //"));
        assert!(!result.contains(" : 1; //"));
        assert!(result.contains("static constexpr uint16_t cmd = 0x0305;"));
    }

    #[test]
    fn test_generate_multiple_packets() {
        let json = r#"[
            {
                "packet_name": "PacketA",
                "command_id": "0x0101",
                "namespace": null,
                "packed": true,
                "header_guard": "RPL_PACKETA_HPP",
                "fields": [
                    {
                        "name": "field_a",
                        "type": "uint8_t",
                        "comment": "Field A"
                    }
                ]
            },
            {
                "packet_name": "PacketB",
                "command_id": "0x0102",
                "namespace": "Test::Ns",
                "packed": false,
                "header_guard": "RPL_PACKETB_HPP",
                "fields": [
                    {
                        "name": "field_b",
                        "type": "uint16_t",
                        "comment": "Field B"
                    }
                ]
            }
        ]"#;

        let results = generate_multiple(json).unwrap();
        assert_eq!(results.len(), 2);

        // Check first packet
        let (name_a, output_a) = &results[0];
        assert_eq!(name_a, "PacketA");
        assert!(output_a.contains("#ifndef RPL_PACKETA_HPP"));
        assert!(output_a.contains("__attribute__((packed)) PacketA"));
        assert!(output_a.contains("uint8_t field_a; // Field A"));

        // Check second packet
        let (name_b, output_b) = &results[1];
        assert_eq!(name_b, "PacketB");
        assert!(output_b.contains("#ifndef RPL_PACKETB_HPP"));
        assert!(output_b.contains("namespace Test::Ns {"));
        assert!(!output_b.contains("__attribute__((packed))")); // packed is false
        assert!(output_b.contains("uint16_t field_b; // Field B"));
    }

    #[test]
    fn test_generate_multiple_packets_with_bit_fields() {
        let json = r#"[
            {
                "packet_name": "BitFieldsPacket",
                "command_id": "0x0103",
                "namespace": null,
                "packed": true,
                "header_guard": "RPL_BITFIELDSPACKET_HPP",
                "fields": [
                    {
                        "name": "status",
                        "type": "uint8_t",
                        "bit_field": 4,
                        "comment": "Status field"
                    },
                    {
                        "name": "flag",
                        "type": "uint8_t",
                        "bit_field": 4,
                        "comment": "Flag field"
                    }
                ]
            }
        ]"#;

        let results = generate_multiple(json).unwrap();
        assert_eq!(results.len(), 1);

        let (name, output) = &results[0];
        assert_eq!(name, "BitFieldsPacket");
        assert!(output.contains("#ifndef RPL_BITFIELDSPACKET_HPP"));
        assert!(output.contains("__attribute__((packed)) BitFieldsPacket"));
        assert!(output.contains("uint8_t status : 4; // Status field"));
        assert!(output.contains("uint8_t flag : 4; // Flag field"));
    }

    #[test]
    fn test_generate_multiple_backwards_compatibility() {
        // Test that single packet still works with generate_multiple
        let json = r#"{
            "packet_name": "SinglePacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_SINGLEPACKET_HPP",
            "fields": [
                {
                    "name": "field",
                    "type": "uint8_t",
                    "comment": "A field"
                }
            ]
        }"#;

        let results = generate_multiple(json).unwrap();
        assert_eq!(results.len(), 1);

        let (name, output) = &results[0];
        assert_eq!(name, "SinglePacket");
        assert!(output.contains("#ifndef RPL_SINGLEPACKET_HPP"));
        assert!(output.contains("__attribute__((packed)) SinglePacket"));
        assert!(output.contains("uint8_t field; // A field"));
    }
}
