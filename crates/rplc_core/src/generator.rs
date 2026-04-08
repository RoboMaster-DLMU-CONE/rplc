use crate::config::Config;
use crate::diagnostics::Severity;
use crate::validator::{c_type_to_bit_field_size, parse_array_type, parse_command_id, validate};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("JSON解析失败: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("配置验证未通过，请检查错误信息")]
    ValidationError,
}

#[derive(Debug, Clone)]
struct BitLayoutField {
    ty: String,
    bits: u32,
    is_array: bool,
    array_size: Option<u32>,
}

#[derive(Debug, Clone)]
struct BitLayoutPlan {
    fields: Vec<BitLayoutField>,
    total_bits: u32,
}

/// 分析位域并生成 BitLayout 计划
/// 只要结构体中包含任何位域，就会生成 BitLayout
fn analyze_bit_layout(config: &Config) -> Option<BitLayoutPlan> {
    let mut has_bit_field = false;
    let mut total_bits: u32 = 0;
    let mut fields = Vec::with_capacity(config.fields.len());

    for field in &config.fields {
        let parsed_type = parse_array_type(&field.ty);

        // 如果无法解析类型，跳过
        let (base_type, arr_size) = match parsed_type {
            Some((base, arr)) => (base, arr),
            None => return None,
        };

        let base_bits = u32::from(c_type_to_bit_field_size(base_type)?) * 8;

        let (field_bits, is_array, array_size) = if let Some(arr_size) = arr_size {
            // 数组字段
            let arr_size = arr_size as u32;
            let field_bits = base_bits * arr_size;
            (field_bits, true, Some(arr_size))
        } else if let Some(bit_width) = field.bit_field {
            // 位域字段
            has_bit_field = true;
            (u32::from(bit_width), false, None)
        } else {
            // 普通字段
            (base_bits, false, None)
        };

        total_bits = total_bits.checked_add(field_bits)?;
        fields.push(BitLayoutField {
            ty: base_type.to_string(),
            bits: field_bits,
            is_array,
            array_size,
        });
    }

    // 只要有任何位域字段，就生成 BitLayout
    if has_bit_field {
        Some(BitLayoutPlan { fields, total_bits })
    } else {
        None
    }
}

fn bytes_from_bits(bits: u32) -> u32 {
    bits.div_ceil(8)
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
    let bit_layout_plan = analyze_bit_layout(&config);

    let mut out = String::new();
    // Header Guard
    out.push_str(&format!("#ifndef {}\n", guard));
    out.push_str(&format!("#define {}\n\n", guard));

    // Includes
    out.push_str("#include <cstdint>\n");
    out.push_str("#include <array>\n");
    if bit_layout_plan.is_some() {
        out.push_str("#include <tuple>\n");
        out.push_str("#include <RPL/Meta/BitstreamTraits.hpp>\n");
    }
    out.push_str("#include <RPL/Meta/PacketTraits.hpp>\n\n");

    // Namespace
    if let Some(ns) = &config.namespace {
        out.push_str(&format!("namespace {} {{\n\n", ns));
    }

    // Add Doxygen-style comment if provided
    if let Some(comment) = &config.comment {
        out.push_str(&format!("/**\n * @brief {}\n */\n", comment));
    }
    out.push_str(&format!("struct {}\n{{\n", config.packet_name));

    // Fields
    for field in &config.fields {
        // 解析数组类型
        if let Some((base_type, arr_size)) = parse_array_type(&field.ty) {
            if let Some(size) = arr_size {
                // 数组类型: std::array<type, size> name;
                out.push_str(&format!("    std::array<{}, {}> {};", base_type, size, field.name));
                if let Some(cmt) = &field.comment {
                    out.push_str(&format!(" ///< {}", cmt));
                }
                out.push('\n');
            } else {
                // 非数组类型: type name;
                out.push_str(&format!("    {} {}", field.ty, field.name));
                if let Some(bf) = field.bit_field {
                    out.push_str(&format!(" : {};", bf));
                } else {
                    out.push(';');
                }
                if let Some(cmt) = &field.comment {
                    out.push_str(&format!(" ///< {}", cmt));
                }
                out.push('\n');
            }
        } else {
            // 解析失败，使用原始类型
            out.push_str(&format!("    {} {}", field.ty, field.name));
            if let Some(bf) = field.bit_field {
                out.push_str(&format!(" : {};", bf));
            } else {
                out.push(';');
            }
            if let Some(cmt) = &field.comment {
                out.push_str(&format!(" ///< {}", cmt));
            }
            out.push('\n');
        }
    }

    let packed = if config.packed {
        "__attribute__((packed))"
    } else {
        ""
    };

    out.push_str(&format!("}} {};\n\n", packed));

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
        "    static constexpr size_t size = {};\n",
        bit_layout_plan
            .as_ref()
            .map(|plan| bytes_from_bits(plan.total_bits))
            .map(|size| size.to_string())
            .unwrap_or_else(|| format!("sizeof({})", config.packet_name))
    ));
    if let Some(plan) = &bit_layout_plan {
        out.push_str("    using BitLayout = std::tuple<\n");
        for (idx, field) in plan.fields.iter().enumerate() {
            let suffix = if idx + 1 == plan.fields.len() {
                ""
            } else {
                ","
            };

            // 根据是否为数组字段生成不同的格式
            if field.is_array {
                if let Some(arr_size) = field.array_size {
                    // 数组字段：Field<std::array<元素类型, 元素个数>, 总位数>
                    out.push_str(&format!(
                        "        Field<std::array<{}>, {}>{}\n",
                        format!("{}, {}", field.ty, arr_size),
                        field.bits,
                        suffix
                    ));
                } else {
                    // 理论上不应该到这里
                    out.push_str(&format!(
                        "        Field<{}, {}>{}\n",
                        field.ty, field.bits, suffix
                    ));
                }
            } else {
                // 非数组字段：Field<类型, 位数>
                out.push_str(&format!(
                    "        Field<{}, {}>{}\n",
                    field.ty, field.bits, suffix
                ));
            }
        }
        out.push_str("    >;\n");
    }
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
        assert!(result.contains("struct BasicPacket"));
        assert!(result.contains("} __attribute__((packed));"));
        assert!(result.contains("uint8_t field1; ///< First field"));
        assert!(result.contains("float field2; ///< Second field"));
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
        assert!(result.contains("struct NamespacePacket"));
        assert!(result.contains("} __attribute__((packed))"));
        assert!(result.contains("uint16_t sensor_id; ///< Sensor identifier"));
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
        assert!(result.contains("int32_t data; ///< Some data"));
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
        assert!(result.contains("double value; ///< A double value"));
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
        assert!(!result.contains("uint32_t no_comment_field; ///<")); // No field comment
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
        assert!(result.contains("struct BitFieldPacket"));
        assert!(result.contains("} __attribute__((packed))"));
        assert!(result.contains("uint8_t status : 4; ///< Status field"));
        assert!(result.contains("uint8_t flag : 3; ///< Flag field"));
        assert!(result.contains("uint8_t reserved : 1; ///< Reserved bit"));
        assert!(result.contains("uint16_t normal_field; ///< Normal field without bit field"));
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
        assert!(result.contains("uint8_t cmd_type : 6; ///< Command type"));
        assert!(result.contains("uint8_t priority : 2; ///< Priority level"));
        assert!(result.contains("uint32_t data; ///< Data payload"));
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
        assert!(result.contains("struct BitFieldsNoComments"));
        assert!(result.contains("} __attribute__((packed))"));
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
    fn test_generate_cross_byte_bit_fields_with_bitlayout() {
        let json = r#"{
            "packet_name": "CrossByteTest",
            "command_id": "0x1002",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_CROSSBYTETEST_HPP",
            "fields": [
                {
                    "name": "val1",
                    "type": "uint32_t",
                    "bit_field": 12,
                    "comment": "takes 1.5 bytes"
                },
                {
                    "name": "val2",
                    "type": "uint32_t",
                    "bit_field": 12,
                    "comment": "takes 1.5 bytes"
                },
                {
                    "name": "val3",
                    "type": "uint8_t",
                    "bit_field": 8,
                    "comment": "takes 1 byte"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("#include <tuple>"));
        assert!(result.contains("#include <RPL/Meta/BitstreamTraits.hpp>"));
        assert!(result.contains("static constexpr size_t size = 4;"));
        assert!(result.contains("using BitLayout = std::tuple<"));
        assert!(result.contains("Field<uint32_t, 12>,"));
        assert!(result.contains("Field<uint32_t, 12>,"));
        assert!(result.contains("Field<uint8_t, 8>"));
    }

    #[test]
    fn test_generate_non_cross_byte_bit_fields_with_bitlayout() {
        let json = r#"{
            "packet_name": "AlignedBitFields",
            "command_id": "0x1003",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_ALIGNEDBITFIELDS_HPP",
            "fields": [
                {
                    "name": "a",
                    "type": "uint8_t",
                    "bit_field": 4
                },
                {
                    "name": "b",
                    "type": "uint8_t",
                    "bit_field": 4
                },
                {
                    "name": "c",
                    "type": "uint8_t",
                    "bit_field": 8
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        // 现在只要包含位域就会生成 BitLayout
        assert!(result.contains("#include <tuple>"));
        assert!(result.contains("using BitLayout = std::tuple<"));
        assert!(result.contains("Field<uint8_t, 4>,"));
        assert!(result.contains("Field<uint8_t, 4>,"));
        assert!(result.contains("Field<uint8_t, 8>"));
        // size 应该使用 bit 计算的字节数
        assert!(result.contains("static constexpr size_t size = 2;")); // 4+4+8 = 16 bits = 2 bytes
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
        assert!(output_a.contains("struct PacketA"));
        assert!(output_a.contains("} __attribute__((packed))"));
        assert!(output_a.contains("uint8_t field_a; ///< Field A"));

        // Check second packet
        let (name_b, output_b) = &results[1];
        assert_eq!(name_b, "PacketB");
        assert!(output_b.contains("#ifndef RPL_PACKETB_HPP"));
        assert!(output_b.contains("namespace Test::Ns {"));
        assert!(!output_b.contains("__attribute__((packed))")); // packed is false
        assert!(output_b.contains("uint16_t field_b; ///< Field B"));
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
        assert!(output.contains("struct BitFieldsPacket"));
        assert!(output.contains("} __attribute__((packed))"));
        assert!(output.contains("uint8_t status : 4; ///< Status field"));
        assert!(output.contains("uint8_t flag : 4; ///< Flag field"));
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
        assert!(output.contains("struct SinglePacket"));
        assert!(output.contains("} __attribute__((packed))"));
        assert!(output.contains("uint8_t field; ///< A field"));
    }

    // ---- Array Type Tests ----

    #[test]
    fn test_generate_with_array_fields() {
        let json = r#"{
            "packet_name": "ArrayPacket",
            "command_id": "0x0104",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_ARRAYPACKET_HPP",
            "fields": [
                {
                    "name": "temperature",
                    "type": "float[3]",
                    "comment": "温度值(摄氏度)"
                },
                {
                    "name": "data",
                    "type": "uint8_t[8]",
                    "comment": "数据数组"
                },
                {
                    "name": "single_field",
                    "type": "uint16_t",
                    "comment": "单值字段"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("std::array<float, 3> temperature; ///< 温度值(摄氏度)"));
        assert!(result.contains("std::array<uint8_t, 8> data; ///< 数据数组"));
        assert!(result.contains("uint16_t single_field; ///< 单值字段"));
        assert!(result.contains("struct ArrayPacket"));
    }

    #[test]
    fn test_generate_with_array_and_namespace() {
        let json = r#"{
            "packet_name": "NamespaceArrayPacket",
            "command_id": "0x0204",
            "namespace": "Robot::Sensors",
            "packed": true,
            "header_guard": "RPL_NAMESPACEARRAYPACKET_HPP",
            "fields": [
                {
                    "name": "sensor_data",
                    "type": "int32_t[4]",
                    "comment": "传感器数据数组"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("namespace Robot::Sensors {"));
        assert!(result.contains("std::array<int32_t, 4> sensor_data; ///< 传感器数据数组"));
        assert!(result.contains("// namespace Robot::Sensors"));
        assert!(result.contains("struct NamespaceArrayPacket"));
    }

    #[test]
    fn test_generate_with_mixed_array_and_bitfield() {
        let json = r#"{
            "packet_name": "MixedArrayBitFieldPacket",
            "command_id": "0x0304",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_MIXEDARRAYBITFIELDPACKET_HPP",
            "fields": [
                {
                    "name": "flags",
                    "type": "uint8_t",
                    "bit_field": 4,
                    "comment": "标志位"
                },
                {
                    "name": "reserved",
                    "type": "uint8_t",
                    "bit_field": 4,
                    "comment": "保留位"
                },
                {
                    "name": "data",
                    "type": "uint16_t[4]",
                    "comment": "数据数组"
                },
                {
                    "name": "checksum",
                    "type": "uint32_t",
                    "comment": "校验和"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("uint8_t flags : 4; ///< 标志位"));
        assert!(result.contains("uint8_t reserved : 4; ///< 保留位"));
        assert!(result.contains("std::array<uint16_t, 4> data; ///< 数据数组"));
        assert!(result.contains("uint32_t checksum; ///< 校验和"));
    }

    #[test]
    fn test_generate_array_various_sizes() {
        let json = r#"{
            "packet_name": "VariousArraySizesPacket",
            "command_id": "0x0404",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_VARIOUSSIZESPACKET_HPP",
            "fields": [
                { "name": "single", "type": "float[1]", "comment": "单元素数组" },
                { "name": "small", "type": "uint8_t[2]", "comment": "小数组" },
                { "name": "medium", "type": "int16_t[16]", "comment": "中等数组" },
                { "name": "large", "type": "double[64]", "comment": "大数组" }
            ]
        }"#;

        let result = generate(json).unwrap();

        assert!(result.contains("std::array<float, 1> single; ///< 单元素数组"));
        assert!(result.contains("std::array<uint8_t, 2> small; ///< 小数组"));
        assert!(result.contains("std::array<int16_t, 16> medium; ///< 中等数组"));
        assert!(result.contains("std::array<double, 64> large; ///< 大数组"));
    }

    #[test]
    fn test_generate_c_cpp_compatibility() {
        let json = r#"{
            "packet_name": "CCompatiblePacket",
            "command_id": "0x0504",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_CCOMPATIBLEPACKET_HPP",
            "fields": [
                {
                    "name": "status",
                    "type": "uint8_t",
                    "bit_field": 4,
                    "comment": "状态"
                },
                {
                    "name": "flag",
                    "type": "uint8_t",
                    "bit_field": 4,
                    "comment": "标志"
                },
                {
                    "name": "value",
                    "type": "float",
                    "comment": "数值"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        // 检查包含正确的头文件
        assert!(result.contains("#include <cstdint>"));
        assert!(!result.contains("#include <stdint.h>"));
        assert!(!result.contains("#ifdef __cplusplus"));
        assert!(!result.contains("#else"));
        assert!(!result.contains("#endif // __cplusplus"));

        // 检查 PacketTraits 生成
        assert!(result.contains("template <>"));
        assert!(result.contains("struct RPL::Meta::PacketTraits<CCompatiblePacket>"));

        // 检查基本结构体
        assert!(result.contains("struct CCompatiblePacket"));
        assert!(result.contains("uint8_t status : 4;"));
        assert!(result.contains("uint8_t flag : 4;"));
        assert!(result.contains("float value;"));
    }

    #[test]
    fn test_generate_bitlayout_with_array_fields() {
        let json = r#"{
            "packet_name": "InteractionFigure",
            "command_id": "0x0401",
            "namespace": null,
            "packed": true,
            "header_guard": "RPL_INTERACTIONFIGURE_HPP",
            "fields": [
                {
                    "name": "figure_name",
                    "type": "uint8_t[3]",
                    "comment": "图形名称"
                },
                {
                    "name": "operate_type",
                    "type": "uint32_t",
                    "bit_field": 3,
                    "comment": "操作类型"
                },
                {
                    "name": "figure_id",
                    "type": "uint8_t",
                    "comment": "图形ID"
                }
            ]
        }"#;

        let result = generate(json).unwrap();

        // 检查 std::array 格式的结构体字段
        assert!(result.contains("std::array<uint8_t, 3> figure_name; ///< 图形名称"));
        
        // 检查 BitLayout 生成
        assert!(result.contains("using BitLayout = std::tuple<"));
        
        // 检查数组字段的 Field<std::array<T, N>, bits> 格式
        assert!(result.contains("Field<std::array<uint8_t, 3>, 24>"));
        
        // 检查位域字段
        assert!(result.contains("Field<uint32_t, 3>"));
        
        // 检查普通字段
        assert!(result.contains("Field<uint8_t, 8>"));
        
        // 检查 size 计算：24 + 3 + 8 = 35 bits，向上取整为 5 bytes
        assert!(result.contains("static constexpr size_t size = 5;"));
    }
}
