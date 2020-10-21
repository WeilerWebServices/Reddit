/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef  _module_TYPES_TCC
#define  _module_TYPES_TCC

#include "module_types.h"

#include "module_reflection.h"



template <class Protocol_>
uint32_t MyStruct::read(Protocol_* iprot) {

  uint32_t xfer = 0;
  std::string fname;
  apache::thrift::protocol::TType ftype;
  int16_t fid;

  ::apache::thrift::reflection::Schema * schema = iprot->getSchema();
  if (schema != nullptr) {
     ::module_reflection_::reflectionInitializer_7958971832214294220(*schema);
    iprot->setNextStructType(MyStruct::_reflection_id);
  }
  xfer += iprot->readStructBegin(fname);

  using apache::thrift::protocol::TProtocolException;



  while (true)
  {
    xfer += iprot->readFieldBegin(fname, ftype, fid);
    if (ftype == apache::thrift::protocol::T_STOP) {
      break;
    }
    switch (fid)
    {
      case 1:
        if (ftype == apache::thrift::protocol::T_I64) {
          xfer += iprot->readI64(this->MyIntField);
          this->__isset.MyIntField = true;
        } else {
          xfer += iprot->skip(ftype);
        }
        break;
      case 2:
        if (ftype == apache::thrift::protocol::T_STRING) {
          xfer += iprot->readString(this->MyStringField);
          this->__isset.MyStringField = true;
        } else {
          xfer += iprot->skip(ftype);
        }
        break;
      default:
        xfer += iprot->skip(ftype);
        break;
    }
    xfer += iprot->readFieldEnd();
  }

  xfer += iprot->readStructEnd();

  return xfer;
}

template <class Protocol_>
uint32_t MyStruct::write(Protocol_* oprot) const {
  uint32_t xfer = 0;
  xfer += oprot->writeStructBegin("MyStruct");
  xfer += oprot->writeFieldBegin("MyIntField", apache::thrift::protocol::T_I64, 1);
  xfer += oprot->writeI64(this->MyIntField);
  xfer += oprot->writeFieldEnd();
  xfer += oprot->writeFieldBegin("MyStringField", apache::thrift::protocol::T_STRING, 2);
  xfer += oprot->writeString(this->MyStringField);
  xfer += oprot->writeFieldEnd();
  xfer += oprot->writeFieldStop();
  xfer += oprot->writeStructEnd();
  return xfer;
}



#endif
