#ifndef __CHANNELTOKEN_H__
#define __CHANNELTOKEN_H__


#include <cstring>
#include <vector>
#include <ostream>
#include <sstream>
#include <iostream>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"

#define HEX_CHARS   "0123456789abcdefABCDEF"
#define VECTOR_LENGTH 810
#define HEX_STRING_LENGTH VECTOR_LENGTH*2

#define NUM_BASE_POINTS 5
#define LENGTH_POINT 129
#define LENGTH_R  32

using namespace rapidjson;

class ChannelToken : public std::vector<uint8_t> {

  
  public:

    std::string toJson() {

      Document json;
      // allocator for memory management
      Document::AllocatorType& allocator = json.GetAllocator();

      // define the document as an object rather than an array
      json.SetObject();

      // 810 bytes => [g-count] [g-len] [g-bytes_i] [g-bytes_count] [c-len] [c-bytes] [r-len] [r-bytes]
      if( VECTOR_LENGTH != this->size())
        return("{}");

      // iterator we are going to be using the whole time
      std::vector<uint8_t>::iterator it = this->begin();

      // Double check the g-count
      if( NUM_BASE_POINTS != *it )
        return("{}");
      it++;

      // Double check the g-len
      if( LENGTH_POINT != *it )
        return("{}");
      it++;

      Value params(kObjectType);
      Value pub_bases(kArrayType);

      for( int i = 0; i< NUM_BASE_POINTS; i++) 
      {
        Value base(kArrayType);
        for( int j = 0; j< LENGTH_POINT; j++) 
        { 
          base.PushBack(*it, allocator);
          it++;
        }
        pub_bases.PushBack(base, allocator);
      }

      params.AddMember("pub_bases", pub_bases, allocator);

      Value com(kObjectType);

      // double check c-len
      if( LENGTH_POINT != *it )
        return("{}");
      it++;

      Value c(kArrayType);
      for( int j = 0; j< LENGTH_POINT; j++) 
      { 
        c.PushBack(*it, allocator);
        it++;
      }

      com.AddMember("c",c,allocator);

      // double check r-len
      if( LENGTH_R != *it )
        return("{}");
      it++;

      Value r(kArrayType);
      for( int j = 0; j< LENGTH_R; j++) 
      { 
        r.PushBack(*it, allocator);
        it++;
      }

      com.AddMember("r",r,allocator);

      // build final json string 
      json.AddMember("com", com, allocator);
      json.AddMember("params", params, allocator);

      StringBuffer sb;
      Writer<StringBuffer> writer(sb);
      json.Accept(writer); 
      return sb.GetString();
    }

    bool fromJson(std::string s) {
      Document json;
      json.Parse(s.c_str());

      eraseAll();

      // Make sure we arent going to get an error when indexing into the JSON
      if(!json.HasMember("params"))
        return false;

      const Value& params = json["params"];

      if(!params.IsObject())
        return false;
      if(!params.HasMember("pub_bases"))
        return false;


      const Value& pub_bases = params["pub_bases"];

      if(!pub_bases.IsArray())
        return false;
      if(!(pub_bases.Size() == SizeType(NUM_BASE_POINTS)))
        return false;

      //Checking the formatting in com ahead of time before we edit the internal vector
      if(!json.HasMember("com"))
        return false;
      const Value& com = json["com"];

      if(!com.IsObject())
        return false;
      if(!com.HasMember("c"))
        return false;
      if(!com.HasMember("r"))
        return false;

      const Value& c = com["c"];
      const Value& r = com["r"];

      if(!c.IsArray())
        return false;
      if(!r.IsArray())
        return false;

      if(!(c.Size() == SizeType(LENGTH_POINT)))
        return false;
      if(!(r.Size() == SizeType(LENGTH_R)))
        return false;

      // Add the header information
      // From here on out, make sure to call cleanupAndFalse() instead of false
      this->push_back(NUM_BASE_POINTS);
      this->push_back(LENGTH_POINT);

      for (SizeType i = 0; i < pub_bases.Size(); i++) 
      {
        const Value& basepoint = pub_bases[i];
        if(!basepoint.IsArray())
          return cleanupAndFalse();
        if(!(basepoint.Size() == SizeType(LENGTH_POINT)))
          return cleanupAndFalse();

        for(SizeType j = 0; j < basepoint.Size(); j++)
        {
          this->push_back(basepoint[j].GetUint64());
        }
      }

      this->push_back(LENGTH_POINT);

      for(SizeType j = 0; j < c.Size(); j++)
        this->push_back(c[j].GetUint64());

      this->push_back(LENGTH_R);

      for(SizeType j = 0; j < r.Size(); j++)
        this->push_back(r[j].GetUint64());

      // Make sure the final length is good
      if(!(this->size() == VECTOR_LENGTH)) 
        return cleanupAndFalse();

      return true;
    }


// Stolen from https://github.com/zeutro/openabe/blob/master/src/include/openabe/utils/zbytestring.h

    bool fromHex(std::string s) {
      if((s.find_first_not_of(HEX_CHARS) != std::string::npos) ||
              (s.size() % 2 != 0)) {
        return false;
      }

      if ( s.length() != HEX_STRING_LENGTH)
        return false;

      std::string hex_str;
      std::stringstream ss;
      int tmp;

      this->clear();
      for (size_t i = 0; i < s.size(); i += 2) {
        hex_str  = s[i];
        hex_str += s[i+1];

        ss << hex_str;
        ss >> std::hex >> tmp;
        this->push_back(tmp & 0xFF);
        ss.clear();
      }
      return true;
    }

    std::string toHex() const {
      std::stringstream ss;
      int hex_len = 2;
      char hex[hex_len+1];
      std::memset(hex, 0, hex_len+1);

      for (std::vector<uint8_t>::const_iterator it = this->begin();
          it != this->end(); ++it) {
        sprintf(hex, "%02X", *it);
        ss << hex;
      }
      return ss.str();
    }

    std::string toLowerHex() const {
      std::stringstream ss;
      int hex_len = 2;
      char hex[hex_len+1];
      std::memset(hex, 0, hex_len+1);

      for (std::vector<uint8_t>::const_iterator it = this->begin() ; it != this->end(); ++it) {
          sprintf(hex, "%02x", *it);
          ss << hex;
      }
      return ss.str();
    }

    void eraseAll() {
      this->erase(this->begin(), this->end());
    }

  private:

    bool cleanupAndFalse() {
      eraseAll();
      return false;
    }

};


#endif