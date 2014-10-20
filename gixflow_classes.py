"""
gixglow_classes.py
Created by Daniel Piekacz on 2014-06-01.
Updated on 2014-06-04.
https://gixtools.net
"""


class NetflowMessageID:
    TemplateV9 = 0
    TemplateV9_Optional = 1
    Template = 2
    Template_Optional = 3
    FlowRecord = 256
    Enterprise = 32768


class NetFlowTemplates:
    Version = 0
    Size = 1
    Template = 2
    Unpack = 3
    Struct = 4


class NetFlowDataTypes:
    In_Bytes = 1
    In_Packets = 2
    Flows = 3
    Protocol = 4
    Src_TOS = 5
    TCP_Flags = 6
    L4_Src_Port = 7
    IPv4_Src_Addr = 8
    Src_Mask = 9
    Input_SNMP = 10
    L4_Dst_Port = 11
    IPv4_Dst_Addr = 12
    Dst_Mask = 13
    Output_SNMP = 14
    IPv4_Next_Hop = 15
    Src_AS = 16
    Dst_AS = 17
    BGP_IPv4_Next_Hop = 18
    Mul_Dst_Packets = 19
    Mul_Dst_Bytes = 20
    Last_Switched = 21
    First_Switched = 22
    Out_Bytes = 23
    Out_Packets = 24
    Min_Packet_Length = 25
    Max_Packet_Length = 26
    IPv6_Src_Addr = 27
    IPv6_Dst_Addr = 28
    IPv6_Src_Mask = 29
    IPv6_Dst_Mask = 30
    IPv6_Flow_Label = 31
    ICMP_Type = 32
    Mul_IGMP_Type = 33
    Sampling_Interval = 34
    Sampling_Algorithm = 35
    Flow_Active_Timeout = 36
    Flow_Inactive_Timeout = 37
    Engine_Type = 38
    Engine_ID = 39
    Total_Bytes_Exported = 40
    Total_Packets_Exported = 41
    Total_Flows_Exported = 42
    # = 43
    IPv4_Src_Prefix = 44
    IPv4_Dst_Prefix = 45
    MPLS_Top_Label_Type = 46
    MPLS_Top_Label_IP_Addr = 47
    Flow_Sampler_ID = 48
    Flow_Sampler_Mode = 49
    Flow_Sampler_Random_Interval = 50
    # = 51
    MinTTL = 52
    MaxTTL = 53
    IPv4_Ident = 54
    Dst_TOS = 55
    In_Src_MAC = 56
    Out_Dst_MAC = 57
    Src_VLAN = 58
    Dst_VLAN = 59
    IP_Proto_Version = 60
    Direction = 61
    IPv6_Next_Hop = 62
    BGP_IPv6_Next_Hop = 63
    IPv6_Option_Headers = 64
    # = 65
    # = 66
    # = 67
    # = 68
    # = 69
    MPLS_Label1 = 70
    MPLS_Label2 = 71
    MPLS_Label3 = 72
    MPLS_Label4 = 73
    MPLS_Label5 = 74
    MPLS_Label6 = 75
    MPLS_Label7 = 76
    MPLS_Label8 = 77
    MPLS_Label9 = 78
    MPLS_Label10 = 79
    In_Dst_MAC = 80
    Out_Src_MAc = 81
    IF_Name = 82
    IF_Desc = 83
    Sampler_Name = 84
    In_Permanent_Bytes = 85
    In_Permanent_Packets = 86
    # = 87
    Fragment_Offset = 88
    Forwarding_status = 89
    MPLS_PAL_Route_Distinguisher = 90
    MPLS_Prefix_Length = 91
    Src_Traffic_Index = 92
    Dst_Traffic_Index = 93
    Application_Desc = 94
    Application_Tag = 95
    Application_Name = 96
    # = 97
    postipDiffServCodePoint = 98
    Mul_Replication_Factor = 99
    # = 100
    # = 101
    Layer2_Packet_Section_Offset = 102
    Layer2_Packet_Section_Size = 103
    Layer2_Packet_Section_Data = 104


class ASNtype:
    Internal = 0
    Unknown = 4294967295


class PrefixExpire:
    # Never - For RFC special IP networks and known prefixes.
    Never = 0
    # 4 weeks - For prefixes where DNS lookup returned data.
    Default = 2419200
    # 2 hours - For prefixes where DNS lookup returned no data or failed.
    Short = 7200


class Protocols:
    ICMP = 1
    TCP = 6
    UDP = 17
    IPV6 = 41
    GRE = 47
    ESP = 50
    AH = 51
    ICMP6 = 58
    L2TP = 115
    SCTP = 132


class TCPflags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class IP2ASN_def_mask:
    IPv4 = "24"
    IPv6 = "48"
