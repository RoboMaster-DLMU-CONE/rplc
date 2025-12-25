use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub bit_field: Option<u8>,
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub packet_name: String,
    pub command_id: String,
    pub namespace: Option<String>,
    #[serde(default = "default_packet")]
    pub packed: bool,
    pub header_guard: Option<String>,
    #[serde(default = "default_comment")]
    pub comment: Option<String>,
    pub fields: Vec<Field>,
}

fn default_packet() -> bool {
    true
}

fn default_comment() -> Option<String> {
    None
}

// New functionality to support multiple configurations
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigOrArray {
    Single(Config),
    Multiple(Vec<Config>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_serialization() {
        let field = Field {
            name: "temperature".to_string(),
            ty: "float".to_string(),
            bit_field: None,
            comment: Some("温度值(摄氏度)".to_string()),
        };

        let json = serde_json::to_string(&field).unwrap();
        assert!(json.contains("temperature"));
        assert!(json.contains("float"));
        assert!(json.contains("温度值"));

        let parsed: Field = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "temperature");
        assert_eq!(parsed.ty, "float");
        assert_eq!(parsed.comment, Some("温度值(摄氏度)".to_string()));
    }

    #[test]
    fn test_field_without_comment() {
        let field = Field {
            name: "sensor_id".to_string(),
            ty: "uint8_t".to_string(),
            bit_field: Some(3),
            comment: None,
        };

        let json = serde_json::to_string(&field).unwrap();
        assert!(json.contains("sensor_id"));
        assert!(json.contains("uint8_t"));

        let parsed: Field = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "sensor_id");
        assert_eq!(parsed.ty, "uint8_t");
        assert_eq!(parsed.comment, None);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            packet_name: "SensorDataPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: Some("RPL_SENSORDATAPACKET_HPP".to_string()),
            comment: None,
            fields: vec![
                Field {
                    name: "sensor_id".to_string(),
                    ty: "uint8_t".to_string(),
                    bit_field: Some(3),
                    comment: Some("传感器ID".to_string()),
                },
                Field {
                    name: "temperature".to_string(),
                    ty: "float".to_string(),
                    bit_field: None,
                    comment: Some("温度值(摄氏度)".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("SensorDataPacket"));
        assert!(json.contains("0x0104"));
        assert!(json.contains("uint8_t"));
        assert!(json.contains("传感器ID"));

        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.packet_name, "SensorDataPacket");
        assert_eq!(parsed.command_id, "0x0104");
        assert_eq!(parsed.namespace, None);
        assert_eq!(parsed.packed, true);
        assert_eq!(
            parsed.header_guard,
            Some("RPL_SENSORDATAPACKET_HPP".to_string())
        );
        assert_eq!(parsed.fields.len(), 2);
        assert_eq!(parsed.fields[0].name, "sensor_id");
        assert_eq!(parsed.fields[0].ty, "uint8_t");
    }

    #[test]
    fn test_config_with_namespace() {
        let config = Config {
            packet_name: "RobotPosition".to_string(),
            command_id: "0x0201".to_string(),
            namespace: Some("Robot::Navigation".to_string()),
            packed: true,
            header_guard: None,
            comment: None,
            fields: vec![Field {
                name: "robot_id".to_string(),
                ty: "uint16_t".to_string(),
                bit_field: None,
                comment: Some("机器人ID".to_string()),
            }],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("RobotPosition"));
        assert!(json.contains("Robot::Navigation"));

        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.namespace, Some("Robot::Navigation".to_string()));
    }

    #[test]
    fn test_config_default_packed_value() {
        // Create JSON without specifying packed field to test default
        let json = r#"{
            "packet_name": "TestPacket",
            "command_id": "0x0101",
            "namespace": null,
            "header_guard": null,
            "fields": []
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.packed, true); // Should default to true
    }

    #[test]
    fn test_config_explicit_packed_false() {
        let config = Config {
            packet_name: "UnpackedPacket".to_string(),
            command_id: "0x0102".to_string(),
            namespace: None,
            packed: false, // Explicitly set to false
            header_guard: None,
            comment: None,
            fields: vec![],
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.packed, false);
    }

    #[test]
    fn test_field_with_bit_field_serialization() {
        let field = Field {
            name: "status_flag".to_string(),
            ty: "uint8_t".to_string(),
            bit_field: Some(3),
            comment: Some("状态标志".to_string()),
        };

        let json = serde_json::to_string(&field).unwrap();
        assert!(json.contains(r#""bit_field":3"#));

        let parsed: Field = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "status_flag");
        assert_eq!(parsed.ty, "uint8_t");
        assert_eq!(parsed.bit_field, Some(3));
        assert_eq!(parsed.comment, Some("状态标志".to_string()));
    }

    #[test]
    fn test_field_without_bit_field_serialization() {
        let field = Field {
            name: "temperature".to_string(),
            ty: "float".to_string(),
            bit_field: None,
            comment: Some("温度值".to_string()),
        };

        let json = serde_json::to_string(&field).unwrap();

        let parsed: Field = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "temperature");
        assert_eq!(parsed.ty, "float");
        assert_eq!(parsed.bit_field, None);
        assert_eq!(parsed.comment, Some("温度值".to_string()));
    }

    #[test]
    fn test_config_with_bit_fields_serialization() {
        let config = Config {
            packet_name: "SensorStatus".to_string(),
            command_id: "0x0301".to_string(),
            namespace: None,
            packed: true,
            header_guard: Some("RPL_SENSORSTATUS_HPP".to_string()),
            comment: Some("传感器状态包".to_string()),
            fields: vec![
                Field {
                    name: "sensor_id".to_string(),
                    ty: "uint8_t".to_string(),
                    bit_field: Some(4),
                    comment: Some("传感器ID".to_string()),
                },
                Field {
                    name: "status_flag".to_string(),
                    ty: "uint8_t".to_string(),
                    bit_field: Some(3),
                    comment: Some("状态标志".to_string()),
                },
                Field {
                    name: "reserved".to_string(),
                    ty: "uint8_t".to_string(),
                    bit_field: Some(1),
                    comment: Some("保留位".to_string()),
                },
                Field {
                    name: "temperature".to_string(),
                    ty: "float".to_string(),
                    bit_field: None,
                    comment: Some("温度值".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains(r#""bit_field":4"#));
        assert!(json.contains(r#""bit_field":3"#));
        assert!(json.contains(r#""bit_field":1"#));
        assert!(json.contains(r#""comment":"传感器状态包""#));

        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.packet_name, "SensorStatus");
        assert_eq!(parsed.comment, Some("传感器状态包".to_string()));
        assert_eq!(parsed.fields.len(), 4);
        assert_eq!(parsed.fields[0].bit_field, Some(4));
        assert_eq!(parsed.fields[1].bit_field, Some(3));
        assert_eq!(parsed.fields[2].bit_field, Some(1));
        assert_eq!(parsed.fields[3].bit_field, None);
    }

    #[test]
    fn test_config_with_packet_comment() {
        let config = Config {
            packet_name: "SensorDataPacket".to_string(),
            command_id: "0x0104".to_string(),
            namespace: None,
            packed: true,
            header_guard: Some("RPL_SENSORDATAPACKET_HPP".to_string()),
            comment: Some("传感器数据包".to_string()),
            fields: vec![
                Field {
                    name: "sensor_id".to_string(),
                    ty: "uint8_t".to_string(),
                    bit_field: None,
                    comment: Some("传感器ID".to_string()),
                },
            ],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("SensorDataPacket"));
        assert!(json.contains("传感器数据包"));
        assert!(json.contains("sensor_id"));

        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.packet_name, "SensorDataPacket");
        assert_eq!(parsed.command_id, "0x0104");
        assert_eq!(parsed.comment, Some("传感器数据包".to_string()));
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields[0].name, "sensor_id");
    }

    #[test]
    fn test_config_without_packet_comment() {
        // Create JSON without specifying comment field to test default
        let json = r#"{
            "packet_name": "TestPacket",
            "command_id": "0x0101",
            "namespace": null,
            "header_guard": null,
            "fields": []
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.comment, None); // Should default to None
    }
}
