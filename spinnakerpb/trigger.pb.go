// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trigger.proto

package spinnakerpb

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Trigger struct {
	// Types that are valid to be assigned to Trigger:
	//	*Trigger_Webhook
	Trigger              isTrigger_Trigger `protobuf_oneof:"trigger"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Trigger) Reset()         { *m = Trigger{} }
func (m *Trigger) String() string { return proto.CompactTextString(m) }
func (*Trigger) ProtoMessage()    {}
func (*Trigger) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c31e6d8b4368946, []int{0}
}
func (m *Trigger) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Trigger) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Trigger.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Trigger) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Trigger.Merge(m, src)
}
func (m *Trigger) XXX_Size() int {
	return m.Size()
}
func (m *Trigger) XXX_DiscardUnknown() {
	xxx_messageInfo_Trigger.DiscardUnknown(m)
}

var xxx_messageInfo_Trigger proto.InternalMessageInfo

type isTrigger_Trigger interface {
	isTrigger_Trigger()
	MarshalTo([]byte) (int, error)
	Size() int
}

type Trigger_Webhook struct {
	Webhook *WebhookTrigger `protobuf:"bytes,1,opt,name=webhook,proto3,oneof"`
}

func (*Trigger_Webhook) isTrigger_Trigger() {}

func (m *Trigger) GetTrigger() isTrigger_Trigger {
	if m != nil {
		return m.Trigger
	}
	return nil
}

func (m *Trigger) GetWebhook() *WebhookTrigger {
	if x, ok := m.GetTrigger().(*Trigger_Webhook); ok {
		return x.Webhook
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Trigger) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Trigger_Webhook)(nil),
	}
}

type WebhookTrigger struct {
	// common
	Type                string   `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	Enabled             bool     `protobuf:"varint,2,opt,name=enabled,proto3" json:"enabled,omitempty"`
	ExpectedArtifactIds []string `protobuf:"bytes,3,rep,name=expectedArtifactIds,proto3" json:"expectedArtifactIds,omitempty"`
	// fields
	Source               string            `protobuf:"bytes,101,opt,name=source,proto3" json:"source,omitempty"`
	PayloadConstraints   map[string]string `protobuf:"bytes,102,rep,name=payloadConstraints,proto3" json:"payloadConstraints,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *WebhookTrigger) Reset()         { *m = WebhookTrigger{} }
func (m *WebhookTrigger) String() string { return proto.CompactTextString(m) }
func (*WebhookTrigger) ProtoMessage()    {}
func (*WebhookTrigger) Descriptor() ([]byte, []int) {
	return fileDescriptor_8c31e6d8b4368946, []int{1}
}
func (m *WebhookTrigger) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *WebhookTrigger) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_WebhookTrigger.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *WebhookTrigger) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WebhookTrigger.Merge(m, src)
}
func (m *WebhookTrigger) XXX_Size() int {
	return m.Size()
}
func (m *WebhookTrigger) XXX_DiscardUnknown() {
	xxx_messageInfo_WebhookTrigger.DiscardUnknown(m)
}

var xxx_messageInfo_WebhookTrigger proto.InternalMessageInfo

func (m *WebhookTrigger) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *WebhookTrigger) GetEnabled() bool {
	if m != nil {
		return m.Enabled
	}
	return false
}

func (m *WebhookTrigger) GetExpectedArtifactIds() []string {
	if m != nil {
		return m.ExpectedArtifactIds
	}
	return nil
}

func (m *WebhookTrigger) GetSource() string {
	if m != nil {
		return m.Source
	}
	return ""
}

func (m *WebhookTrigger) GetPayloadConstraints() map[string]string {
	if m != nil {
		return m.PayloadConstraints
	}
	return nil
}

func init() {
	proto.RegisterType((*Trigger)(nil), "spinnakerpb.Trigger")
	proto.RegisterType((*WebhookTrigger)(nil), "spinnakerpb.WebhookTrigger")
	proto.RegisterMapType((map[string]string)(nil), "spinnakerpb.WebhookTrigger.PayloadConstraintsEntry")
}

func init() { proto.RegisterFile("trigger.proto", fileDescriptor_8c31e6d8b4368946) }

var fileDescriptor_8c31e6d8b4368946 = []byte{
	// 286 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0xc1, 0x4a, 0xf3, 0x40,
	0x14, 0x85, 0xff, 0x69, 0x7e, 0x1b, 0x73, 0xa3, 0x22, 0xa3, 0xe8, 0xa0, 0x10, 0x42, 0x57, 0x59,
	0x05, 0x69, 0x17, 0x8a, 0x3b, 0x2b, 0x05, 0x5d, 0x08, 0x32, 0x08, 0xae, 0x27, 0xc9, 0x6d, 0x0d,
	0x09, 0x33, 0xc3, 0x64, 0xaa, 0xe6, 0xbd, 0x7c, 0x08, 0x97, 0x3e, 0x82, 0xe4, 0x49, 0xc4, 0x24,
	0x05, 0xc5, 0xea, 0xee, 0x1e, 0xce, 0x37, 0xe7, 0x70, 0x18, 0xd8, 0xb6, 0x26, 0x5f, 0x2c, 0xd0,
	0xc4, 0xda, 0x28, 0xab, 0xa8, 0x5f, 0xe9, 0x5c, 0x4a, 0x51, 0xa0, 0xd1, 0xc9, 0xe8, 0x06, 0xdc,
	0xbb, 0xce, 0xa5, 0xa7, 0xe0, 0x3e, 0x61, 0xf2, 0xa0, 0x54, 0xc1, 0x48, 0x48, 0x22, 0x7f, 0x7c,
	0x1c, 0x7f, 0x21, 0xe3, 0xfb, 0xce, 0xeb, 0xe9, 0xab, 0x7f, 0x7c, 0x45, 0x4f, 0x3d, 0x70, 0xfb,
	0x86, 0xd1, 0xcb, 0x00, 0x76, 0xbe, 0x83, 0x94, 0xc2, 0x7f, 0x5b, 0x6b, 0x6c, 0x33, 0x3d, 0xde,
	0xde, 0x94, 0x81, 0x8b, 0x52, 0x24, 0x25, 0x66, 0x6c, 0x10, 0x92, 0x68, 0x93, 0xaf, 0x24, 0x3d,
	0x81, 0x3d, 0x7c, 0xd6, 0x98, 0x5a, 0xcc, 0x2e, 0x8c, 0xcd, 0xe7, 0x22, 0xb5, 0xd7, 0x59, 0xc5,
	0x9c, 0xd0, 0x89, 0x3c, 0xbe, 0xce, 0xa2, 0x07, 0x30, 0xac, 0xd4, 0xd2, 0xa4, 0xc8, 0xb0, 0x6d,
	0xe8, 0x15, 0x4d, 0x81, 0x6a, 0x51, 0x97, 0x4a, 0x64, 0x97, 0x4a, 0x56, 0xd6, 0x88, 0x5c, 0xda,
	0x8a, 0xcd, 0x43, 0x27, 0xf2, 0xc7, 0x93, 0x3f, 0x96, 0xc5, 0xb7, 0x3f, 0x5e, 0xcd, 0xa4, 0x35,
	0x35, 0x5f, 0x13, 0x77, 0x34, 0x83, 0xc3, 0x5f, 0x70, 0xba, 0x0b, 0x4e, 0x81, 0x75, 0x3f, 0xfb,
	0xf3, 0xa4, 0xfb, 0xb0, 0xf1, 0x28, 0xca, 0x25, 0xb6, 0x9b, 0x3d, 0xde, 0x89, 0xf3, 0xc1, 0x19,
	0x99, 0x6e, 0xbd, 0x36, 0x01, 0x79, 0x6b, 0x02, 0xf2, 0xde, 0x04, 0x24, 0x19, 0xb6, 0xff, 0x34,
	0xf9, 0x08, 0x00, 0x00, 0xff, 0xff, 0x97, 0x0e, 0xa8, 0xb9, 0xb8, 0x01, 0x00, 0x00,
}

func (m *Trigger) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Trigger) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Trigger) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Trigger != nil {
		{
			size := m.Trigger.Size()
			i -= size
			if _, err := m.Trigger.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
		}
	}
	return len(dAtA) - i, nil
}

func (m *Trigger_Webhook) MarshalTo(dAtA []byte) (int, error) {
	return m.MarshalToSizedBuffer(dAtA[:m.Size()])
}

func (m *Trigger_Webhook) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	if m.Webhook != nil {
		{
			size, err := m.Webhook.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintTrigger(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}
func (m *WebhookTrigger) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *WebhookTrigger) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *WebhookTrigger) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.PayloadConstraints) > 0 {
		for k := range m.PayloadConstraints {
			v := m.PayloadConstraints[k]
			baseI := i
			i -= len(v)
			copy(dAtA[i:], v)
			i = encodeVarintTrigger(dAtA, i, uint64(len(v)))
			i--
			dAtA[i] = 0x12
			i -= len(k)
			copy(dAtA[i:], k)
			i = encodeVarintTrigger(dAtA, i, uint64(len(k)))
			i--
			dAtA[i] = 0xa
			i = encodeVarintTrigger(dAtA, i, uint64(baseI-i))
			i--
			dAtA[i] = 0x6
			i--
			dAtA[i] = 0xb2
		}
	}
	if len(m.Source) > 0 {
		i -= len(m.Source)
		copy(dAtA[i:], m.Source)
		i = encodeVarintTrigger(dAtA, i, uint64(len(m.Source)))
		i--
		dAtA[i] = 0x6
		i--
		dAtA[i] = 0xaa
	}
	if len(m.ExpectedArtifactIds) > 0 {
		for iNdEx := len(m.ExpectedArtifactIds) - 1; iNdEx >= 0; iNdEx-- {
			i -= len(m.ExpectedArtifactIds[iNdEx])
			copy(dAtA[i:], m.ExpectedArtifactIds[iNdEx])
			i = encodeVarintTrigger(dAtA, i, uint64(len(m.ExpectedArtifactIds[iNdEx])))
			i--
			dAtA[i] = 0x1a
		}
	}
	if m.Enabled {
		i--
		if m.Enabled {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x10
	}
	if len(m.Type) > 0 {
		i -= len(m.Type)
		copy(dAtA[i:], m.Type)
		i = encodeVarintTrigger(dAtA, i, uint64(len(m.Type)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintTrigger(dAtA []byte, offset int, v uint64) int {
	offset -= sovTrigger(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Trigger) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Trigger != nil {
		n += m.Trigger.Size()
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Trigger_Webhook) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Webhook != nil {
		l = m.Webhook.Size()
		n += 1 + l + sovTrigger(uint64(l))
	}
	return n
}
func (m *WebhookTrigger) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Type)
	if l > 0 {
		n += 1 + l + sovTrigger(uint64(l))
	}
	if m.Enabled {
		n += 2
	}
	if len(m.ExpectedArtifactIds) > 0 {
		for _, s := range m.ExpectedArtifactIds {
			l = len(s)
			n += 1 + l + sovTrigger(uint64(l))
		}
	}
	l = len(m.Source)
	if l > 0 {
		n += 2 + l + sovTrigger(uint64(l))
	}
	if len(m.PayloadConstraints) > 0 {
		for k, v := range m.PayloadConstraints {
			_ = k
			_ = v
			mapEntrySize := 1 + len(k) + sovTrigger(uint64(len(k))) + 1 + len(v) + sovTrigger(uint64(len(v)))
			n += mapEntrySize + 2 + sovTrigger(uint64(mapEntrySize))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovTrigger(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozTrigger(x uint64) (n int) {
	return sovTrigger(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Trigger) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTrigger
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Trigger: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Trigger: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Webhook", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrigger
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrigger
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &WebhookTrigger{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.Trigger = &Trigger_Webhook{v}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTrigger(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTrigger
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTrigger
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *WebhookTrigger) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTrigger
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: WebhookTrigger: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: WebhookTrigger: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTrigger
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTrigger
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Type = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Enabled", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Enabled = bool(v != 0)
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpectedArtifactIds", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTrigger
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTrigger
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ExpectedArtifactIds = append(m.ExpectedArtifactIds, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 101:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Source", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTrigger
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTrigger
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Source = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 102:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PayloadConstraints", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTrigger
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTrigger
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.PayloadConstraints == nil {
				m.PayloadConstraints = make(map[string]string)
			}
			var mapkey string
			var mapvalue string
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowTrigger
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					wire |= uint64(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				fieldNum := int32(wire >> 3)
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowTrigger
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthTrigger
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey < 0 {
						return ErrInvalidLengthTrigger
					}
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = string(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var stringLenmapvalue uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowTrigger
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapvalue |= uint64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapvalue := int(stringLenmapvalue)
					if intStringLenmapvalue < 0 {
						return ErrInvalidLengthTrigger
					}
					postStringIndexmapvalue := iNdEx + intStringLenmapvalue
					if postStringIndexmapvalue < 0 {
						return ErrInvalidLengthTrigger
					}
					if postStringIndexmapvalue > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = string(dAtA[iNdEx:postStringIndexmapvalue])
					iNdEx = postStringIndexmapvalue
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipTrigger(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if skippy < 0 {
						return ErrInvalidLengthTrigger
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.PayloadConstraints[mapkey] = mapvalue
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTrigger(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTrigger
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTrigger
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTrigger(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTrigger
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTrigger
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthTrigger
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthTrigger
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowTrigger
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipTrigger(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthTrigger
				}
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthTrigger = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTrigger   = fmt.Errorf("proto: integer overflow")
)