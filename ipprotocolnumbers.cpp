#include "ipprotocolnumbers.h"

// Initialize the map with protocol numbers and names
const std::unordered_map<int, std::string> IPProtocolNumbers::ipProtocolNumbers = {
    {0, "HOPOPT"}, {1, "ICMP"}, {2, "IGMP"}, {3, "GGP"},
    {4, "IP-in-IP"}, {5, "ST"}, {6, "TCP"}, {7, "CBT"},
    {8, "EGP"}, {9, "IGP"}, {10, "BBN-RCC-MON"}, {11, "NVP-II"},
    {12, "PUP"}, {13, "ARGUS"}, {14, "EMCON"}, {15, "XNET"},
    {16, "CHAOS"}, {17, "UDP"}, {18, "MUX"}, {19, "DCN-MEAS"},
    {20, "HMP"}, {21, "PRM"}, {22, "XNS-IDP"}, {23, "TRUNK-1"},
    {24, "TRUNK-2"}, {25, "LEAF-1"}, {26, "LEAF-2"}, {27, "RDP"},
    {28, "IRTP"}, {29, "ISO-TP4"}, {30, "NETBLT"}, {31, "MFE-NSP"},
    {32, "MERIT-INP"}, {33, "DCCP"}, {34, "3PC"}, {35, "IDPR"},
    {36, "XTP"}, {37, "DDP"}, {38, "IDPR-CMTP"}, {39, "TP++"},
    {40, "IL"}, {41, "IPv6"}, {42, "SDRP"}, {43, "IPv6-Route"},
    {44, "IPv6-Frag"}, {45, "IDRP"}, {46, "RSVP"}, {47, "GRE"},
    {48, "DSR"}, {49, "BNA"}, {50, "ESP"}, {51, "AH"},
    {52, "I-NLSP"}, {53, "SWIPE"}, {54, "NARP"}, {55, "MOBILE"},
    {56, "TLSP"}, {57, "SKIP"}, {58, "ICMPv6"}, {59, "IPv6-NoNxt"},
    {60, "IPv6-Opts"}, {61, "CFTP"}, {62, "SAT-EXPAK"}, {63, "KRYPTOLAN"},
    {64, "RVD"}, {65, "IPPC"}, {66, "SAT-MON"}, {67, "VISA"},
    {68, "IPCV"}, {69, "CPNX"}, {70, "CPHB"}, {71, "WSN"},
    {72, "PVP"}, {73, "BR-SAT-MON"}, {74, "SUN-ND"}, {75, "WB-MON"},
    {76, "WB-EXPAK"}, {77, "ISO-IP"}, {78, "VMTP"}, {79, "SECURE-VMTP"},
    {80, "VINES"}, {81, "TTP"}, {82, "NSFNET-IGP"}, {83, "DGP"},
    {84, "TCF"}, {85, "EIGRP"}, {86, "OSPFIGP"}, {87, "Sprite-RPC"},
    {88, "LARP"}, {89, "MTP"}, {90, "AX.25"}, {91, "IPIP"},
    {92, "MICP"}, {93, "SCC-SP"}, {94, "ETHERIP"}, {95, "ENCAP"},
    {96, "GMTP"}, {97, "IFMP"}, {98, "PNNI"}, {99, "PIM"},
    {100, "ARIS"}, {101, "SCPS"}, {102, "QNX"}, {103, "A/N"},
    {104, "IPComp"}, {105, "SNP"}, {106, "Compaq-Peer"}, {107, "IPX-in-IP"},
    {108, "VRRP"}, {109, "PGM"}, {110, "L2TP"}, {111, "DDX"},
    {112, "IATP"}, {113, "STP"}, {114, "SRP"}, {115, "UTI"},
    {116, "SMP"}, {117, "SM"}, {118, "PTP"}, {119, "ISIS over IPv4"},
    {120, "FIRE"}, {121, "CRTP"}, {122, "CRUDP"}, {123, "SSCOPMCE"},
    {124, "IPLT"}, {125, "SPS"}, {126, "PIPE"}, {127, "SCTP"},
    {128, "FC"}, {129, "RSVP-E2E-IGNORE"}, {130, "Mobility Header"},
    {131, "UDPLite"}, {132, "MPLS-in-IP"}, {133, "MANET"}, {134, "HIP"},
    {135, "Shim6"}, {136, "WESP"}, {137, "ROHC"}, {138, "Ethernet"},
    {139, "AGGFRAG"}, {140, "GTPv1-U"}, {141, "MPLS"}, {142, "PBB"},
    {143, "GTPv2-C"}, {144, "GTP-C"}, {145, "GTP-U"}, {146, "GTP'"},
    {147, "MPLS Control"}, {148, "PIMv2"}, {149, "WLAN"}, {150, "Frame Relay"},
    {151, "PPP"}, {152, "ATM"}, {153, "DSL"}, {154, "GSM"},
    {155, "EDGE"}, {156, "UMTS"}, {157, "LTE"}, {158, "NR"},
    {159, "DSRC"}, {160, "CAN"}, {161, "FlexRay"}, {162, "MOST"},
    {163, "TSN"}, {164, "AFDX"}, {165, "ARINC 429"}, {166, "ARINC 664"},
    {167, "ARINC 825"}, {168, "TTEthernet"}, {169, "Profinet"}, {170, "EtherCAT"},
    {171, "Ethernet/IP"}, {172, "POWERLINK"}, {173, "SERCOS"}, {174, "CIP"},
    {175, "HART"}, {176, "Modbus"}, {177, "FOUNDATION Fieldbus"}, {178, "Profibus"},
    {179, "CC-Link"}, {180, "BACnet"}, {181, "LonWorks"}, {182, "KNX"},
    {183, "ZigBee"}, {184, "Bluetooth"}, {185, "Wi-Fi"}, {186, "Z-Wave"},
    {187, "EnOcean"}, {188, "LoRaWAN"}, {189, "Sigfox"}, {190, "NB-IoT"},
    {191, "Cat-M1"}, {192, "5G NR"}, {193, "6LoWPAN"}, {194, "Thread"},
    {195, "Weave"}, {196, "Matter"}, {197, "EAP"}, {198, "Diameter"},
    {199, "Radius"}, {200, "SIP"}, {201, "H.323"}, {202, "MGCP"},
    {203, "RTSP"}, {204, "RTP"}, {205, "SRTP"}, {206, "SCTP"},
    {207, "Q.931"}, {208, "H.248"}, {209, "X.25"}, {210, "FR"},
    {211, "ATM AAL5"}, {212, "PPP"}, {213, "Ethernet"}, {214, "802.11"},
    {215, "CDMA2000"}, {216, "GSM"}, {217, "UMTS"}, {218, "LTE"},
    {219, "5G"}, {220, "NB-IoT"}, {221, "Cat-M1"}, {222, "ZigBee"},
    {223, "Thread"}, {224, "LoRaWAN"}, {225, "Bluetooth"}, {226, "Wi-Fi"},
    {227, "Ethernet"}, {228, "Token Ring"}, {229, "FDDI"}, {230, "ATM"},
    {231, "MPLS"}, {232, "Frame Relay"}, {233, "PPP"}, {234, "VPLS"},
    {235, "Ethernet"}, {236, "802.3"}, {237, "802.11"}, {238, "802.15.4"},
    {239, "802.16"}, {240, "802.20"}, {241, "802.21"}, {242, "802.22"},
    {243, "GSM"}, {244, "CDMA2000"}, {245, "UMTS"}, {246, "LTE"},
    {247, "5G"}, {248, "NB-IoT"}, {249, "Cat-M1"}, {250, "ZigBee"},
    {251, "Thread"}, {252, "LoRaWAN"}, {253, "Bluetooth"}, {254, "Wi-Fi"},
    {255, "Reserved"}      // Reserved
};

std::string IPProtocolNumbers::getProtocolName(int protocolNumber) 
{
    auto it = ipProtocolNumbers.find(protocolNumber);
    if (it != ipProtocolNumbers.end()) 
    {
        return it->second;
    } 
    else 
    {
        return "Unknown protocol";
    }
}
