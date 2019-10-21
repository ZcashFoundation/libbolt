#ifndef __CHANNELCLOSURE_H__
#define __CHANNELCLOSURE_H__


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
#define CHANNEL_CLOSURE_VECTOR_LENGTH 1426
#define CHANNEL_CLOSURE_HEX_STRING_LENGTH CHANNEL_CLOSURE_VECTOR_LENGTH*2

#define CHANNEL_CLOSURE_G2_LENGTH 129

#define CHANNEL_CLOSURE_A_ARRAY_SIZE 4 //2 <--- TODO GABE I thought these are supposed to be 2 long?
#define CHANNEL_CLOSURE_B_ARRAY_SIZE 4 //2

using namespace rapidjson;

class ChannelClosure : public std::vector<uint8_t> {

  
  public:

    std::string toJson() {

      Document json;
      // allocator for memory management
      Document::AllocatorType& allocator = json.GetAllocator();

      // define the document as an object rather than an array
      json.SetObject();

      if( CHANNEL_CLOSURE_VECTOR_LENGTH != this->size())
        return("{}");

      // iterator we are going to be using the whole time
      std::vector<uint8_t>::iterator it = this->begin();

      // Double check the a length
      if( CHANNEL_CLOSURE_G2_LENGTH != *it )
        return("{}");
      it++;

      Value a(kArrayType);
      for( int j = 0; j< CHANNEL_CLOSURE_G2_LENGTH; j++) 
      { 
        a.PushBack(*it, allocator);
        it++;
      }

      // Double check the b length
      if( CHANNEL_CLOSURE_G2_LENGTH != *it )
        return("{}");
      it++;

      Value b(kArrayType);
      for( int j = 0; j< CHANNEL_CLOSURE_G2_LENGTH; j++) 
      { 
        b.PushBack(*it, allocator);
        it++;
      }

      // Double check the c length
      if( CHANNEL_CLOSURE_G2_LENGTH != *it )
        return("{}");
      it++;

      Value c(kArrayType);
      for( int j = 0; j< CHANNEL_CLOSURE_G2_LENGTH; j++) 
      { 
        c.PushBack(*it, allocator);
        it++;
      }

      json.AddMember("a", a, allocator);
      json.AddMember("b", b, allocator);
      json.AddMember("c", c, allocator);

      Value A(kArrayType);


      // Check how many things there are 
      if( CHANNEL_CLOSURE_A_ARRAY_SIZE != *it )
        return("{}");
      it++;

      // Check the size of the things
      if( CHANNEL_CLOSURE_G2_LENGTH != *it )
        return("{}");
      it++;


      for (int i =0; i <CHANNEL_CLOSURE_A_ARRAY_SIZE; i++)
      {
        Value temp(kArrayType);
        for( int j = 0; j< CHANNEL_CLOSURE_G2_LENGTH; j++) 
        { 
          temp.PushBack(*it, allocator);
          it++;
        }
        A.PushBack(temp, allocator);
      }

      Value B(kArrayType);

      // Check how many things there are 
      if( CHANNEL_CLOSURE_B_ARRAY_SIZE != *it )
        return("{}");
      it++;

      // Check the size of the things
      if( CHANNEL_CLOSURE_G2_LENGTH != *it )
        return("{}");
      it++;


      for (int i =0; i <CHANNEL_CLOSURE_A_ARRAY_SIZE; i++)
      {
        Value temp(kArrayType);
        for( int j = 0; j< CHANNEL_CLOSURE_G2_LENGTH; j++) 
        { 
          temp.PushBack(*it, allocator);
          it++;
        }
        B.PushBack(temp, allocator);
      }

      json.AddMember("A", A, allocator);
      json.AddMember("B", B, allocator);

      StringBuffer sb;
      Writer<StringBuffer> writer(sb);
      json.Accept(writer); 
      return sb.GetString();
    }


    bool fromJson(std::string s) {
      Document json;
      json.Parse(s.c_str());

      eraseAll();

      // // Make sure we arent going to get an error when indexing into the JSON
      if(!json.HasMember("a"))
        return false;
      if(!json.HasMember("b"))
        return false;
      if(!json.HasMember("c"))
        return false;
      if(!json.HasMember("A"))
        return false;
      if(!json.HasMember("B"))
        return false;


      const Value& a = json["a"];
      const Value& b = json["b"];
      const Value& c = json["c"];
      const Value& A = json["A"];
      const Value& B = json["B"];

      if(!a.IsArray())
        return false;      
      if(!b.IsArray())
        return false;
      if(!c.IsArray())
        return false;      
      if(!A.IsArray())
        return false;    
      if(!B.IsArray())
        return false;

      if(!(a.Size() == SizeType(CHANNEL_CLOSURE_G2_LENGTH)))
        return false;  
      if(!(b.Size() == SizeType(CHANNEL_CLOSURE_G2_LENGTH)))
        return false;
      if(!(c.Size() == SizeType(CHANNEL_CLOSURE_G2_LENGTH)))
        return false;

      if(!(A.Size() == SizeType(CHANNEL_CLOSURE_A_ARRAY_SIZE)))
        return false;
      if(!(B.Size() == SizeType(CHANNEL_CLOSURE_B_ARRAY_SIZE)))
        return false;    

      // Add the header information
      // From here on out, make sure to call cleanupAndFalse() instead of false
      
      // a
      this->push_back(CHANNEL_CLOSURE_G2_LENGTH);

      for(SizeType j = 0; j < a.Size(); j++)
        this->push_back(a[j].GetUint64());

      // b
      this->push_back(CHANNEL_CLOSURE_G2_LENGTH);

      for(SizeType j = 0; j < c.Size(); j++)
        this->push_back(b[j].GetUint64());

      // c
      this->push_back(CHANNEL_CLOSURE_G2_LENGTH);

      for(SizeType j = 0; j < c.Size(); j++)
        this->push_back(c[j].GetUint64());

      // A
      this->push_back(CHANNEL_CLOSURE_A_ARRAY_SIZE);
      this->push_back(CHANNEL_CLOSURE_G2_LENGTH);

      for (SizeType i = 0; i < A.Size(); i++) 
      {
        const Value& vec = A[i];
        if(!vec.IsArray())
          return cleanupAndFalse();
        if(!(vec.Size() == SizeType(CHANNEL_CLOSURE_G2_LENGTH)))
          return cleanupAndFalse();

        for(SizeType j = 0; j < vec.Size(); j++)
        {
          this->push_back(vec[j].GetUint64());
        }
      }

      // B
      this->push_back(CHANNEL_CLOSURE_B_ARRAY_SIZE);
      this->push_back(CHANNEL_CLOSURE_G2_LENGTH);
      for (SizeType i = 0; i < B.Size(); i++) 
      {
        const Value& vec = B[i];
        if(!vec.IsArray())
          return cleanupAndFalse();
        if(!(vec.Size() == SizeType(CHANNEL_CLOSURE_G2_LENGTH)))
          return cleanupAndFalse();

        for(SizeType j = 0; j < vec.Size(); j++)
        {
          this->push_back(vec[j].GetUint64());
        }
      }    

      // Make sure the final length is good
      if(!(this->size() == CHANNEL_CLOSURE_VECTOR_LENGTH)) 
        return cleanupAndFalse();

      return true;
    }


// Stolen from https://github.com/zeutro/openabe/blob/master/src/include/openabe/utils/zbytestring.h

    bool fromHex(std::string s) {
      if((s.find_first_not_of(HEX_CHARS) != std::string::npos) ||
              (s.size() % 2 != 0)) {
        return false;
      }

      if ( s.length() != CHANNEL_CLOSURE_HEX_STRING_LENGTH)
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