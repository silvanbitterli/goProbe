//go:build darwin
// +build darwin

package protocols

// IPProtocols maps all protocol values to their name. These are taken from the distributions /etc/protocols file
var IPProtocols = map[int]string{
	0:   "HOPOPT", // added to fit consistency tests
	1:   "ICMP",
	2:   "IGMP",
	3:   "GGP",
	4:   "IP-ENCAP",
	5:   "ST2",
	6:   "TCP",
	7:   "CBT",
	8:   "EGP",
	9:   "IGP",
	10:  "BBN-RCC-MON",
	11:  "NVP-II",
	12:  "PUP",
	13:  "ARGUS",
	14:  "EMCON",
	15:  "XNET",
	16:  "CHAOS",
	17:  "UDP",
	18:  "MUX",
	19:  "DCN-MEAS",
	20:  "HMP",
	21:  "PRM",
	22:  "XNS-IDP",
	23:  "TRUNK-1",
	24:  "TRUNK-2",
	25:  "LEAF-1",
	26:  "LEAF-2",
	27:  "RDP",
	28:  "IRTP",
	29:  "ISO-TP4",
	30:  "NETBLT",
	31:  "MFE-NSP",
	32:  "MERIT-INP",
	33:  "DCCP",
	34:  "3PC",
	35:  "IDPR",
	36:  "XTP",
	37:  "DDP",
	38:  "IDPR-CMTP",
	39:  "TP++",
	40:  "IL",
	41:  "IPV6",
	42:  "SDRP",
	43:  "IPV6-ROUTE",
	44:  "IPV6-FRAG",
	45:  "IDRP",
	46:  "RSVP",
	47:  "GRE",
	48:  "DSR",
	49:  "BNA",
	50:  "ESP",
	51:  "AH",
	52:  "I-NLSP",
	53:  "SWIPE",
	54:  "NARP",
	55:  "MOBILE",
	56:  "TLSP",
	57:  "SKIP",
	58:  "IPV6-ICMP",
	59:  "IPV6-NONXT",
	60:  "IPV6-OPTS",
	62:  "CFTP",
	64:  "SAT-EXPAK",
	65:  "KRYPTOLAN",
	66:  "RVD",
	67:  "IPPC",
	69:  "SAT-MON",
	70:  "VISA",
	71:  "IPCV",
	72:  "CPNX",
	73:  "CPHB",
	74:  "WSN",
	75:  "PVP",
	76:  "BR-SAT-MON",
	77:  "SUN-ND",
	78:  "WB-MON",
	79:  "WB-EXPAK",
	80:  "ISO-IP",
	81:  "VMTP",
	82:  "SECURE-VMTP",
	83:  "VINES",
	84:  "TTP",
	85:  "NSFNET-IGP",
	86:  "DGP",
	87:  "TCF",
	88:  "EIGRP",
	89:  "OSPFIGP",
	90:  "SPRITE-RPC",
	91:  "LARP",
	92:  "MTP",
	93:  "AX.25",
	94:  "IPIP",
	95:  "MICP",
	96:  "SCC-SP",
	97:  "ETHERIP",
	98:  "ENCAP",
	100: "GMTP",
	101: "IFMP",
	102: "PNNI",
	103: "PIM",
	104: "ARIS",
	105: "SCPS",
	106: "QNX",
	107: "A/N",
	108: "IPCOMP",
	109: "SNP",
	110: "COMPAQ-PEER",
	111: "IPX-IN-IP",
	112: "CARP",
	113: "PGM",
	115: "L2TP",
	116: "DDX",
	117: "IATP",
	118: "STP",
	119: "SRP",
	120: "UTI",
	121: "SMP",
	122: "SM",
	123: "PTP",
	124: "ISIS",
	125: "FIRE",
	126: "CRTP",
	127: "CRUDP",
	128: "SSCOPMCE",
	129: "IPLT",
	130: "SPS",
	131: "PIPE",
	132: "SCTP",
	133: "FC",
	134: "RSVP-E2E-IGNORE",
	135: "MOBILITY-HEADER",
	136: "UDPLITE",
	137: "MPLS-IN-IP",
	138: "MANET",
	139: "HIP",
	140: "SHIM6",
	141: "WESP",
	142: "ROHC",
	240: "PFSYNC",
	258: "DIVERT",
	255: "UNKNOWN",
}

// IPProtocolIDs maps protocol names to their numeric value
var IPProtocolIDs = map[string]int{
	"hopopt":          0, // added to fit consistency tests
	"icmp":            1,
	"igmp":            2,
	"ggp":             3,
	"ip-encap":        4,
	"st2":             5,
	"tcp":             6,
	"cbt":             7,
	"egp":             8,
	"igp":             9,
	"bbn-rcc-mon":     10,
	"nvp-ii":          11,
	"pup":             12,
	"argus":           13,
	"emcon":           14,
	"xnet":            15,
	"chaos":           16,
	"udp":             17,
	"mux":             18,
	"dcn-meas":        19,
	"hmp":             20,
	"prm":             21,
	"xns-idp":         22,
	"trunk-1":         23,
	"trunk-2":         24,
	"leaf-1":          25,
	"leaf-2":          26,
	"rdp":             27,
	"irtp":            28,
	"iso-tp4":         29,
	"netblt":          30,
	"mfe-nsp":         31,
	"merit-inp":       32,
	"dccp":            33,
	"3pc":             34,
	"idpr":            35,
	"xtp":             36,
	"ddp":             37,
	"idpr-cmtp":       38,
	"tp++":            39,
	"il":              40,
	"ipv6":            41,
	"sdrp":            42,
	"ipv6-route":      43,
	"ipv6-frag":       44,
	"idrp":            45,
	"rsvp":            46,
	"gre":             47,
	"dsr":             48,
	"bna":             49,
	"esp":             50,
	"ah":              51,
	"i-nlsp":          52,
	"swipe":           53,
	"narp":            54,
	"mobile":          55,
	"tlsp":            56,
	"skip":            57,
	"ipv6-icmp":       58,
	"ipv6-nonxt":      59,
	"ipv6-opts":       60,
	"cftp":            62,
	"sat-expak":       64,
	"kryptolan":       65,
	"rvd":             66,
	"ippc":            67,
	"sat-mon":         69,
	"visa":            70,
	"ipcv":            71,
	"cpnx":            72,
	"cphb":            73,
	"wsn":             74,
	"pvp":             75,
	"br-sat-mon":      76,
	"sun-nd":          77,
	"wb-mon":          78,
	"wb-expak":        79,
	"iso-ip":          80,
	"vmtp":            81,
	"secure-vmtp":     82,
	"vines":           83,
	"ttp":             84,
	"nsfnet-igp":      85,
	"dgp":             86,
	"tcf":             87,
	"eigrp":           88,
	"ospfigp":         89,
	"sprite-rpc":      90,
	"larp":            91,
	"mtp":             92,
	"ax.25":           93,
	"ipip":            94,
	"micp":            95,
	"scc-sp":          96,
	"etherip":         97,
	"encap":           98,
	"gmtp":            100,
	"ifmp":            101,
	"pnni":            102,
	"pim":             103,
	"aris":            104,
	"scps":            105,
	"qnx":             106,
	"a/n":             107,
	"ipcomp":          108,
	"snp":             109,
	"compaq-peer":     110,
	"ipx-in-ip":       111,
	"carp":            112,
	"pgm":             113,
	"l2tp":            115,
	"ddx":             116,
	"iatp":            117,
	"stp":             118,
	"srp":             119,
	"uti":             120,
	"smp":             121,
	"sm":              122,
	"ptp":             123,
	"isis":            124,
	"fire":            125,
	"crtp":            126,
	"crudp":           127,
	"sscopmce":        128,
	"iplt":            129,
	"sps":             130,
	"pipe":            131,
	"sctp":            132,
	"fc":              133,
	"rsvp-e2e-ignore": 134,
	"mobility-header": 135,
	"udplite":         136,
	"mpls-in-ip":      137,
	"manet":           138,
	"hip":             139,
	"shim6":           140,
	"wesp":            141,
	"rohc":            142,
	"pfsync":          240,
	"divert":          258,
	"unknown":         255,
}
