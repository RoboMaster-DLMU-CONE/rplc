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
    let diags = validate(&config);
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

    for field in &config.fields {
        out.push_str(&format!("    {} {};", field.ty, field.name));
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
        "    static constexpr uint16_t cmd = {};\n",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Field};

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
        assert!(result.contains("static constexpr uint16_t cmd = 260;")); // 0x0104 = 260
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
        assert!(result.contains("static constexpr uint16_t cmd = 43981;")); // 0xABCD = 43981
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
}
