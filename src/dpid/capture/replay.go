// replay.go — v5.29 T4: 回放侧的公共入口(开发机离线跑)。
//
// dpid_replay 读 pcap, 逐包送进 capture 的同一套解析函数 —— 复用, 不复制
// 代码。pcap 是 dpid 录制器写的 LINKTYPE_RAW(101, 裸 IP 包); 以太网
// pcap(LINKTYPE 1)也支持, 剥头后按 RAWIP 解析。
package capture

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// ParseForReplay dpid_replay 的解析入口: b = 完整 pcap 记录数据,
// ethernet = pcap network==1(LINKTYPE_ETHERNET)。
func ParseForReplay(b []byte, ts time.Time, ethernet bool) (Event, ParseResult) {
	if ethernet {
		if len(b) < recEthernetBytes {
			return Event{}, ParseMalformed
		}
		et := binary.BigEndian.Uint16(b[12:14])
		if !ethTypes[et] {
			return Event{}, ParseIgnore
		}
		b = b[recEthernetBytes:]
	}
	return parseRawIPPacket(b, ts)
}

// PcapReader 顺序读 pcap 包(只支持标准 magic, 微秒精度)。
type PcapReader struct {
	r        io.Reader
	Ethernet bool // network==1
	Snaplen  uint32
	hdr      [16]byte
	hdrRead  bool
	packets  uint64
}

// NewPcapReader 读全局头并判链路类型。
func NewPcapReader(r io.Reader) (*PcapReader, error) {
	var g [24]byte
	if _, err := io.ReadFull(r, g[:]); err != nil {
		return nil, err
	}
	magic := binary.LittleEndian.Uint32(g[0:4])
	if magic != 0xa1b2c3d4 {
		if binary.BigEndian.Uint32(g[0:4]) == 0xa1b2c3d4 {
			return nil, errors.New("replay: big-endian pcap 不支持(录制器写本机字节序)")
		}
		return nil, errors.New("replay: 不是 pcap(magic 不符)")
	}
	network := binary.LittleEndian.Uint32(g[20:24])
	if network != recLinkTypeRAW && network != 1 {
		return nil, errors.New("replay: 链路类型不是 RAW(101)/Ethernet(1)")
	}
	return &PcapReader{r: r, Ethernet: network == 1, Snaplen: binary.LittleEndian.Uint32(g[16:20]), hdrRead: true}, nil
}

// Next 读下一个包; io.EOF = 结束。
func (p *PcapReader) Next() ([]byte, time.Time, error) {
	if _, err := io.ReadFull(p.r, p.hdr[:]); err != nil {
		if err == io.EOF {
			return nil, time.Time{}, io.EOF
		}
		return nil, time.Time{}, err
	}
	tsSec := binary.LittleEndian.Uint32(p.hdr[0:4])
	tsUsec := binary.LittleEndian.Uint32(p.hdr[4:8])
	incl := binary.LittleEndian.Uint32(p.hdr[8:12])
	if incl > 1<<26 {
		return nil, time.Time{}, errors.New("replay: 单包长度异常(>64MB), 文件损坏?")
	}
	buf := make([]byte, incl)
	if _, err := io.ReadFull(p.r, buf); err != nil {
		return nil, time.Time{}, err
	}
	p.packets++
	return buf, time.Unix(int64(tsSec), int64(tsUsec)*1000), nil
}

// Packets 已读包数。
func (p *PcapReader) Packets() uint64 { return p.packets }
