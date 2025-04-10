import pyshark
import argparse

BEGIN_FLAG = "7e"
ESCAPE_FLAG = "7d"
ESCAPE_MAP = {
    "5e": "7e",
    "5d": "7d"
}

object_table = {}
writer_table = {}
reader_table = {}

name_candidates = [
    "spike_state_node",
    "spike_button_status",
    "spike_device_status",
    "spike_power_status",
    "wheel_motor_speeds",
    "motor_reset_count",
    "speaker_tone",
    "color_sensor_mode",
    "ultrasonic_sensor_mode",
    "imu_init",
]

def unescape_data(hex_list):
    result = []
    i = 0
    while i < len(hex_list):
        if hex_list[i] == ESCAPE_FLAG and i + 1 < len(hex_list):
            mapped = ESCAPE_MAP.get(hex_list[i + 1])
            if mapped:
                result.append(mapped)
                i += 2
                continue
        result.append(hex_list[i])
        i += 1
    return result

def extract_xrce_packets_from_pcap(pcap_path):
    cap = pyshark.FileCapture(pcap_path, display_filter="usb")
    xrce_packets = []
    buffers = {"IN": {"capturing": False, "buffer": [], "base_frame": None, "base_time": None},
               "OUT": {"capturing": False, "buffer": [], "base_frame": None, "base_time": None}}

    for pkt in cap:
        try:
            frame_no = int(pkt.frame_info.number)
            time = float(pkt.sniff_timestamp)
            direction = "IN" if getattr(pkt.usb, 'endpoint_address_direction', '') == "1" else "OUT"

            if len(pkt.layers) > 1 and hasattr(pkt.layers[1], 'usb_capdata'):
                capdata = pkt.layers[1].usb_capdata.replace(":", "").lower()
                hex_bytes = [capdata[i:i+2] for i in range(0, len(capdata), 2)]
                dir_buffer = buffers[direction]
                i = 0
                while i < len(hex_bytes):
                    byte = hex_bytes[i]
                    if byte == BEGIN_FLAG:
                        if dir_buffer["capturing"] and dir_buffer["buffer"]:
                            raw = unescape_data(dir_buffer["buffer"])
                            if len(raw) >= 5:
                                size_lsb = int(raw[3], 16)
                                size_msb = int(raw[4], 16)
                                payload_size = size_lsb + (size_msb << 8)
                                expected_len = payload_size + 5 + 2
                                if len(raw) >= expected_len:
                                    packet_bytes = raw[:expected_len]
                                    xrce_packets.append({
                                        'frame_no': dir_buffer["base_frame"],
                                        'time': dir_buffer["base_time"],
                                        'direction': direction,
                                        'data': packet_bytes
                                    })
                            dir_buffer["buffer"] = []
                        dir_buffer["capturing"] = True
                        dir_buffer["base_frame"] = frame_no
                        dir_buffer["base_time"] = time
                        dir_buffer["buffer"] = ['7e']
                    elif dir_buffer["capturing"]:
                        dir_buffer["buffer"].append(byte)
                    i += 1
        except Exception as e:
            print(f"[!] Error processing frame: {e}")
            continue

    cap.close()
    return xrce_packets

def decode_create_client(payload):
    if len(payload) < 13:
        return "    create_client: (payload too short)"
    xrce_cookie = ''.join(chr(int(b, 16)) for b in payload[0:4])
    xrce_version_major = int(payload[4], 16)
    xrce_version_minor = int(payload[5], 16)
    xrce_vendor_id = (int(payload[6], 16) << 8) + int(payload[7], 16)
    client_key = ''.join(payload[8:12])
    session_id = int(payload[12], 16)
    return f"""\
    create_client:
      xrce_cookie   : {xrce_cookie}
      xrce_version  : {xrce_version_major}.{xrce_version_minor}
      xrce_vendor_id: 0x{xrce_vendor_id:04X}
      client_key    : {client_key}
      session_id    : 0x{session_id:02X}"""

def decode_create(payload):
    request_id = (int(payload[0], 16) << 8) + int(payload[1], 16)

    object_id_high = int(payload[2], 16)
    object_id_low = int(payload[3], 16)
    object_id = (object_id_high << 8) + object_id_low

    object_prefix = (object_id_high << 4) | (object_id_low >> 4)
    object_kind = object_id_low & 0x0F

    object_variant = int(payload[4], 16)

    object_variant_map = {
        0x01: "PARTICIPANT",
        0x02: "TOPIC",
        0x03: "PUBLISHER",
        0x04: "SUBSCRIBER",
        0x05: "DATAWRITER",
        0x06: "DATAREADER",
    }
    object_variant_str = object_variant_map.get(object_variant, f"UNKNOWN (0x{object_variant:02X})")

    if object_kind == 0x01:  # PARTICIPANT
        str_len = (
            int(payload[8], 16) +
            (int(payload[9], 16) << 8) +
            (int(payload[10], 16) << 16) +
            (int(payload[11], 16) << 24)
        )
        name_bytes = payload[12:12 + str_len]
        name = ''.join(chr(int(b, 16)) for b in name_bytes if 0x20 <= int(b, 16) <= 0x7E)

        domain_id = (int(payload[-2], 16) << 8) + int(payload[-1], 16)

        return f"""\
    create:
      request_id  : 0x{request_id:04X}
      object_id   : 0x{object_id:04X}
        object_prefix : 0x{object_prefix:03X}
        object_kind   : 0x{object_kind:02X}
      object_variant: 0x{object_variant:02X} ({object_variant_str})
      name        : {name}
      domain_id   : {domain_id}"""

    elif object_kind == 0x02:  # TOPIC
        topic_name_len = (
            int(payload[12], 16) +
            (int(payload[13], 16) << 8) +
            (int(payload[14], 16) << 16) +
            (int(payload[15], 16) << 24)
        )
        topic_start = 16
        topic_end = topic_start + topic_name_len
        topic_name_bytes = payload[topic_start:topic_end]
        topic_name = ''.join(chr(int(b, 16)) for b in topic_name_bytes if 0x20 <= int(b, 16) <= 0x7E)

        type_len_pos = topic_end + 4
        type_name_len = (
            int(payload[type_len_pos], 16) +
            (int(payload[type_len_pos+1], 16) << 8) +
            (int(payload[type_len_pos+2], 16) << 16) +
            (int(payload[type_len_pos+3], 16) << 24)
        )
        type_name_start = type_len_pos + 4
        type_name_end = type_name_start + type_name_len
        type_name_bytes = payload[type_name_start:type_name_end]
        type_name = ''.join(chr(int(b, 16)) for b in type_name_bytes if 0x20 <= int(b, 16) <= 0x7E)

        return f"""\
    create:
      request_id  : 0x{request_id:04X}
      object_id   : 0x{object_id:04X}
        object_prefix : 0x{object_prefix:03X}
        object_kind   : 0x{object_kind:02X}
      object_variant: 0x{object_variant:02X} ({object_variant_str})
      topic_name  : {topic_name}
      type_name   : {type_name}"""

    elif object_kind == 0x03:  # PUBLISHER
        length = int(payload[8], 16) + (int(payload[9], 16) << 8) + (int(payload[10], 16) << 16) + (int(payload[11], 16) << 24)
        base_offset = 12 + length
        base_object_id = (int(payload[base_offset], 16) << 8) + int(payload[base_offset + 1], 16)

        return f"""\
    create:
      request_id  : 0x{request_id:04X}
      object_id   : 0x{object_id:04X}
        object_prefix : 0x{object_prefix:03X}
        object_kind   : 0x{object_kind:02X}
      object_variant: 0x{object_variant:02X} ({object_variant_str})
      base_object_id: 0x{base_object_id:04X}"""

    elif object_kind == 0x04:  # SUBSCRIBER
        length = int(payload[8], 16) + (int(payload[9], 16) << 8) + (int(payload[10], 16) << 16) + (int(payload[11], 16) << 24)
        base_offset = 12 + length
        base_object_id = (int(payload[base_offset], 16) << 8) + int(payload[base_offset + 1], 16)

        return f"""\
    create:
      request_id  : 0x{request_id:04X}
      object_id   : 0x{object_id:04X}
        object_prefix : 0x{object_prefix:03X}
        object_kind   : 0x{object_kind:02X}
      object_variant: 0x{object_variant:02X} ({object_variant_str})
      base_object_id: 0x{base_object_id:04X}"""

    elif object_kind == 0x05:  # DATAWRITER
        length = int(payload[8], 16) + (int(payload[9], 16) << 8) + (int(payload[10], 16) << 16) + (int(payload[11], 16) << 24)
        base_offset = 12 + length
        base_object_id = (int(payload[base_offset], 16) << 8) + int(payload[base_offset + 1], 16)

        return f"""\
    create:
      request_id  : 0x{request_id:04X}
      object_id   : 0x{object_id:04X}
        object_prefix : 0x{object_prefix:03X}
        object_kind   : 0x{object_kind:02X}
      object_variant: 0x{object_variant:02X} ({object_variant_str})
      base_object_id: 0x{base_object_id:04X}"""

    elif object_kind == 0x06:  # DATAREADER
        length = int(payload[8], 16) + (int(payload[9], 16) << 8) + (int(payload[10], 16) << 16) + (int(payload[11], 16) << 24)
        base_offset = 12 + length
        base_object_id = (int(payload[base_offset], 16) << 8) + int(payload[base_offset + 1], 16)

        return f"""\
    create:
      request_id  : 0x{request_id:04X}
      object_id   : 0x{object_id:04X}
        object_prefix : 0x{object_prefix:03X}
        object_kind   : 0x{object_kind:02X}
      object_variant: 0x{object_variant:02X} ({object_variant_str})
      base_object_id: 0x{base_object_id:04X}"""

    else:
        return f"""\
    create:
      request_id  : 0x{request_id:04X}
      object_id   : 0x{object_id:04X}
        object_prefix : 0x{object_prefix:03X}
        object_kind   : 0x{object_kind:02X}
      object_variant: 0x{object_variant:02X} ({object_variant_str})
      (unsupported object_kind, skipping detailed decode)"""

def decode_write_data(payload):
    if len(payload) < 4:
        return "    write_data: (payload too short)"

    request_id = (int(payload[0], 16) << 8) + int(payload[1], 16)
    object_id = (int(payload[2], 16) << 8) + int(payload[3], 16)

    return f"""\
    write_data:
      request_id: 0x{request_id:04X}
      object_id : 0x{object_id:04X}"""

def decode_read_data(payload):
    if len(payload) < 4:
        return "    read_data: (payload too short)"

    request_id = (int(payload[0], 16) << 8) + int(payload[1], 16)
    object_id = (int(payload[2], 16) << 8) + int(payload[3], 16)

    return f"""\
    read_data:
      request_id: 0x{request_id:04X}
      object_id : 0x{object_id:04X}"""

def decode_data(payload):
    if len(payload) < 2:
        return "    data: (payload too short)"

    object_id = (int(payload[0], 16) << 8) + int(payload[1], 16)

    return f"""\
    data:
      object_id : 0x{object_id:04X}"""

def decode_xrce_message(payload_bytes):
    if len(payload_bytes) < 4:
        return "  XRCE Message: (too short)"

    session_id = int(payload_bytes[0], 16)
    stream_id = int(payload_bytes[1], 16)
    sequence_nr = int(payload_bytes[2], 16) + (int(payload_bytes[3], 16) << 8)

    result = f"""\
  XRCE Message Header:
    session_id   : 0x{session_id:02X}
    stream_id    : 0x{stream_id:02X}
    sequence_nr  : {sequence_nr}
"""

    cursor = 4
    while cursor + 4 <= len(payload_bytes):
        submessage_id = int(payload_bytes[cursor], 16)
        flags = int(payload_bytes[cursor + 1], 16)
        submessage_length = int(payload_bytes[cursor + 2], 16) + (int(payload_bytes[cursor + 3], 16) << 8)

        submessage_type = {
            0x00: "CREATE_CLIENT",
            0x01: "CREATE",
            0x02: "GET_INFO",
            0x03: "DELETE",
            0x04: "STATUS_AGENT",
            0x05: "STATUS",
            0x06: "INFO",
            0x07: "WRITE_DATA",
            0x08: "READ_DATA",
            0x09: "DATA",
            0x0A: "ACKNACK",
            0x0B: "HEARTBEAT",
            0x0C: "RESET",
            0x0D: "FRAGMENT",
            0x0E: "TIMESTAMP",
            0x0F: "TIMESTAMP_REPLY",
        }.get(submessage_id, f"UNKNOWN (0x{submessage_id:02X})")

        result += "\n"
        result += f"""\
  XRCE Submessage Header:
    submessage_id: 0x{submessage_id:02X} ({submessage_type})
    flags        : 0x{flags:02X}
    length       : {submessage_length}
"""

        cursor += 4
        if cursor + submessage_length > len(payload_bytes):
            #result += "    (incomplete submessage payload)\n"
            result += "    (incomplete submessage payload)"
            break

        submessage_payload = payload_bytes[cursor:cursor + submessage_length]

        sub_decoder = {
            0x00: decode_create_client,
            0x01: decode_create,
            0x07: decode_write_data,
            0x08: decode_read_data,
            0x09: decode_data,
        }.get(submessage_id)

        if sub_decoder:
            result += sub_decoder(submessage_payload)
        else:
            # result += "    (no decoder available)\n"
            result += "    (no decoder available)"

        result += "\n"
        cursor += submessage_length

    return result

def print_xrce_packets(packets, mode="xrce", decode=False):
    packets = sorted(packets, key=lambda x: x['frame_no'])

    for pkt in packets:
        if mode == "xrce":
            payload = pkt['data'][5:-2]
            hex_str = ' '.join(payload)
        else:
            hex_str = ' '.join(pkt['data'])

        print(f"{pkt['frame_no']:>5}  {pkt['time']:.6f}  {pkt['direction']:<3}  {hex_str}")

        if decode and mode == "xrce":
            print()
            print(decode_xrce_message(payload))
            # print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract XRCE packets from pcap.")
    parser.add_argument("input", help="Input pcapng file path")
    parser.add_argument("--mode", choices=["serial", "xrce"], default="xrce",
                        help="Dump mode: 'serial' for XRCE-Serial, 'xrce' for XRCE packet only (default)")
    parser.add_argument("--decode", action="store_true",
                        help="Decode XRCE messages into human-readable format")
    args = parser.parse_args()

    packets = extract_xrce_packets_from_pcap(args.input)
    print_xrce_packets(packets, mode=args.mode, decode=args.decode)

