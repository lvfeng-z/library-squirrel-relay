package main

// 线协议帧编解码与帧级校验。
//
// 帧是中继与客户端之间唯一的传输单位，布局如下（多字节整数均为大端）：
//
//	+---------+---------+--------+----------+--------+-----------------+
//	| magic   | version | type   | streamID | length | payload         |
//	| 2 字节  | 1 字节  | 1 字节 | 4 字节   | 4 字节 | length 字节     |
//	+---------+---------+--------+----------+--------+-----------------+
//
// magic 固定 "LS"（0x4C 0x53），同时兼作单端口上区分线协议流量与 HTTP 流量的嗅探前缀。
// 帧类型是封闭白名单，未知类型或 streamID 语义不符均视为协议违规，读侧立即断连。
// 线协议完整契约（字段语义/信令流/错误码/限额）见 PROTOCOL.md。

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	protoMagic      = "LS"
	protoVersion    = 1
	frameHeaderSize = 12
)

// 帧类型（封闭白名单，新增类型必须同步修订 PROTOCOL.md）
const (
	frameHello       byte = 0x01 // 连接首帧：角色与意图声明（客户端→中继，streamID=0）
	frameWelcome     byte = 0x02 // HELLO 的接受应答（中继→客户端，streamID=0）
	frameError       byte = 0x03 // 拒绝或错误，发送后断连（双向，streamID=0）
	frameStreamOpen  byte = 0x04 // 中继→分享方：新虚拟流到达（streamID=新分配的流 ID）
	frameStreamClose byte = 0x05 // 流正常结束（双向，streamID=目标流）
	frameData        byte = 0x06 // 流数据（密文，中继盲转不解析，streamID≠0）
	framePing        byte = 0x07 // 保活探测（双向，streamID=0）
	framePong        byte = 0x08 // 保活应答（双向，streamID=0）
	frameRevoke      byte = 0x09 // 分享方撤销会话（仅隧道连接，streamID=0）
	frameResult      byte = 0x0A // 控制操作应答（中继→分享方，streamID=0）
)

var errProtocol = errors.New("协议违规")

// isControlFrame 控制帧（必须 streamID=0）
func isControlFrame(t byte) bool {
	switch t {
	case frameHello, frameWelcome, frameError, framePing, framePong, frameRevoke, frameResult:
		return true
	}
	return false
}

// isStreamFrame 流帧（必须 streamID≠0）
func isStreamFrame(t byte) bool {
	return t == frameData || t == frameStreamClose || t == frameStreamOpen
}

// frame 单帧的解码形态
type frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

// readFrame 从连接读取一帧并做帧级校验。
// magic/version/帧类型/streamID 语义任一不符、或负载长度超过 maxPayload，返回 errProtocol。
func readFrame(r io.Reader, maxPayload int) (frame, error) {
	var head [frameHeaderSize]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return frame{}, err
	}
	if string(head[0:2]) != protoMagic {
		return frame{}, errProtocol
	}
	if head[2] != protoVersion {
		return frame{}, errProtocol
	}
	typ := head[3]
	sid := binary.BigEndian.Uint32(head[4:8])
	length := binary.BigEndian.Uint32(head[8:12])
	switch {
	case !isControlFrame(typ) && !isStreamFrame(typ):
		return frame{}, errProtocol
	case isControlFrame(typ) && sid != 0:
		return frame{}, errProtocol
	case isStreamFrame(typ) && sid == 0:
		return frame{}, errProtocol
	}
	if int(length) > maxPayload {
		return frame{}, errProtocol
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return frame{}, err
		}
	}
	return frame{Type: typ, StreamID: sid, Payload: payload}, nil
}

// writeFrame 编码并写出一帧；单次 Write 保证帧原子性（并发写同一连接须由调用方串行化）。
func writeFrame(w io.Writer, typ byte, streamID uint32, payload []byte) error {
	buf := make([]byte, frameHeaderSize+len(payload))
	buf[0] = protoMagic[0]
	buf[1] = protoMagic[1]
	buf[2] = protoVersion
	buf[3] = typ
	binary.BigEndian.PutUint32(buf[4:8], streamID)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(payload)))
	copy(buf[frameHeaderSize:], payload)
	_, err := w.Write(buf)
	return err
}

// mustJSON 序列化协议载荷；载荷均为静态结构体，序列化失败属程序错误，直接 panic
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("协议载荷序列化失败: %v", err))
	}
	return b
}

// wireErr 帧层错误的载荷结构（code 枚举见 PROTOCOL.md 错误码表）
type wireErr struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e wireErr) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// helloPayload HELLO 载荷。字段集为封闭白名单：解码拒绝一切未知字段，
// 确保协议面不存在密钥交换/任意路径等未定义信息的携带通道。
type helloPayload struct {
	Role           string     `json:"role"`                     // sharer | recipient
	Action         string     `json:"action,omitempty"`         // 仅 sharer：register | bind
	Token          string     `json:"token,omitempty"`          // bind 与 recipient 拨号必填
	InstanceID     string     `json:"instanceId"`               // 设备绑定实例 ID（客户端自报，溯源用）
	PasswordHash   string     `json:"passwordHash,omitempty"`   // hex(sha256(访问密码))，可选；明文密码永不在线路上出现
	ExpireSeconds  *int64     `json:"expireSeconds,omitempty"`  // 仅 register：nil=用中继默认；0=无限期；>0=自定义秒数
	Meta           *shareMeta `json:"meta,omitempty"`           // 仅 register：落地页文字元数据
	CandidateAddrs []string   `json:"candidateAddrs,omitempty"` // 仅 register：V2 直连候选地址（预留位，本期仅存储不消费）
}

// shareMeta 落地页文字元数据（预览最小化：仅文字，无任何图像）
type shareMeta struct {
	Title     string   `json:"title"`
	WorkCount int64    `json:"workCount"`
	Source    string   `json:"source"`
	WorksName []string `json:"worksName,omitempty"` // 各作品名明文（register 上传，bind 复原不携带）；顺序对齐分享清单
}

// decodeHello 严格解析 HELLO 载荷：未知字段或尾随多余内容一律拒绝
func decodeHello(b []byte) (helloPayload, error) {
	var h helloPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, err
	}
	if dec.More() {
		return h, errors.New("HELLO 载荷含尾随内容")
	}
	return h, nil
}

// welcomePayload WELCOME 载荷
type welcomePayload struct {
	Token     string `json:"token,omitempty"` // register 应答：新生成的分享 token
	ExpiresAt int64  `json:"expiresAt"`       // 会话到期时刻（unix 毫秒，0=无限期）
}

// resultPayload RESULT 载荷（控制操作应答）
type resultPayload struct {
	OK     bool   `json:"ok"`
	Action string `json:"action"`
}
