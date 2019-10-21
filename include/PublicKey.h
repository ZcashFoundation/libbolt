#ifndef __PUBLICKEY_H__
#define __PUBLICKEY_H__


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
#define PUBLIC_KEY_VECTOR_LENGTH 1174
#define PUBLIC_KEY_HEX_STRING_LENGTH PUBLIC_KEY_VECTOR_LENGTH*2

#define PUBLIC_KEY_X_LENGTH 65
#define PUBLIC_KEY_Y_LENGTH 65

#define PUBLIC_KEY_Z_LENGTH 4
#define PUBLIC_KEY_Z_POINT_LENGTH 65

#define PUBLIC_KEY_Z2_LENGTH 4
#define PUBLIC_KEY_Z2_POINT_LENGTH 129

#define PUBLIC_KEY_W_LENGTH 4 //2
#define PUBLIC_KEY_W_POINT_LENGTH 65//130

using namespace rapidjson;

class PublicKey : public std::vector<uint8_t> {

  
  public:

    std::string toJson() {

      Document json;
      // allocator for memory management
      Document::AllocatorType& allocator = json.GetAllocator();

      // define the document as an object rather than an array
      json.SetObject();

      if( PUBLIC_KEY_VECTOR_LENGTH != this->size())
        return("{}");

      // iterator we are going to be using the whole time
      std::vector<uint8_t>::iterator it = this->begin();

      // Double check the X length
      if( PUBLIC_KEY_X_LENGTH != *it )
        return("{}");
      it++;

      Value X(kArrayType);
      for( int j = 0; j< PUBLIC_KEY_X_LENGTH; j++) 
      { 
        X.PushBack(*it, allocator);
        it++;
      }

      // Double check the Y length
      if( PUBLIC_KEY_Y_LENGTH != *it )
        return("{}");
      it++;

      Value Y(kArrayType);
      for( int j = 0; j< PUBLIC_KEY_Y_LENGTH; j++) 
      { 
        Y.PushBack(*it, allocator);
        it++;
      }

      // Double check the Z number
      if( PUBLIC_KEY_Z_LENGTH != *it )
        return("{}");
      it++;

      // ... and that they are the correct length
      if( PUBLIC_KEY_Z_POINT_LENGTH != *it )
        return("{}");
      it++;

      Value Z(kArrayType);
      for( int i = 0; i< PUBLIC_KEY_Z_LENGTH; i++) 
      { 
        Value vec(kArrayType);
        for( int j = 0; j< PUBLIC_KEY_Z_POINT_LENGTH; j++) 
        { 
          vec.PushBack(*it, allocator);
          it++;
        }
        Z.PushBack(vec, allocator);
      }

      // Double check the Z2 number
      if( PUBLIC_KEY_Z2_LENGTH != *it )
        return("{}");
      it++;

      // ... and that they are the correct length
      if( PUBLIC_KEY_Z2_POINT_LENGTH != *it )
        return("{}");
      it++;

      Value Z2(kArrayType);
      for( int i = 0; i< PUBLIC_KEY_Z2_LENGTH; i++) 
      { 
        Value vec(kArrayType);
        for( int j = 0; j< PUBLIC_KEY_Z2_POINT_LENGTH; j++) 
        { 
          vec.PushBack(*it, allocator);
          it++;
        }
        Z2.PushBack(vec, allocator);
      }

      // Double check the W number
      if( PUBLIC_KEY_W_LENGTH != *it )
        return("{}");
      it++;

      // ... and that they are the correct length
      if( PUBLIC_KEY_W_POINT_LENGTH != *it )
        return("{}");
      it++;

      Value W(kArrayType);
      for( int j = 0; j< PUBLIC_KEY_W_LENGTH; j++) 
      { 
        Value vec(kArrayType);
        for( int j = 0; j< PUBLIC_KEY_W_POINT_LENGTH; j++) 
        { 
          vec.PushBack(*it, allocator);
          it++;
        }
        W.PushBack(vec, allocator);
      }

      // build final json string 
      json.AddMember("X", X, allocator);
      json.AddMember("Y", Y, allocator);
      json.AddMember("Z", Z, allocator);
      json.AddMember("Z2", Z2, allocator);
      json.AddMember("W", W, allocator);

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
      if(!json.HasMember("X"))
        return false;
      if(!json.HasMember("Y"))
        return false;
      if(!json.HasMember("Z"))
        return false;
      if(!json.HasMember("Z2"))
        return false;
      if(!json.HasMember("W"))
        return false;

      const Value& X = json["X"];
      const Value& Y = json["Y"];
      const Value& Z = json["Z"];
      const Value& Z2 = json["Z2"];
      const Value& W = json["W"];

      if(!X.IsArray())
        return false;
      if(!Y.IsArray())
        return false;
      if(!Z.IsArray())
        return false;
      if(!Z2.IsArray())
        return false;
      if(!W.IsArray())
        return false;

      if(!(Z.Size() == SizeType(PUBLIC_KEY_Z_LENGTH)))
        return false;  
      if(!(Z2.Size() == SizeType(PUBLIC_KEY_Z2_LENGTH)))
        return false;
      if(!(W.Size() == SizeType(PUBLIC_KEY_W_LENGTH)))
        return false;

      // Add the header information
      // From here on out, make sure to call cleanupAndFalse() instead of false
      
      // X
      this->push_back(PUBLIC_KEY_X_LENGTH);

      for(SizeType j = 0; j < X.Size(); j++)
        this->push_back(X[j].GetUint64());

      // Y
      this->push_back(PUBLIC_KEY_Y_LENGTH);

      for(SizeType j = 0; j < Y.Size(); j++)
        this->push_back(Y[j].GetUint64());      

      // Z
      this->push_back(PUBLIC_KEY_Z_LENGTH);

      this->push_back(PUBLIC_KEY_Z_POINT_LENGTH);

      for (SizeType i = 0; i < Z.Size(); i++) 
      {
        const Value& vec = Z[i];
        if(!vec.IsArray())
          return cleanupAndFalse();
        if(!(vec.Size() == SizeType(PUBLIC_KEY_Z_POINT_LENGTH)))
          return cleanupAndFalse();

        for(SizeType j = 0; j < vec.Size(); j++)
        {
          this->push_back(vec[j].GetUint64());
        }
      }

      //Z2
      this->push_back(PUBLIC_KEY_Z2_LENGTH);

      this->push_back(PUBLIC_KEY_Z2_POINT_LENGTH);

      for (SizeType i = 0; i < Z2.Size(); i++) 
      {
        const Value& vec = Z2[i];
        if(!vec.IsArray())
          return cleanupAndFalse();
        if(!(vec.Size() == SizeType(PUBLIC_KEY_Z2_POINT_LENGTH)))
          return cleanupAndFalse();

        for(SizeType j = 0; j < vec.Size(); j++)
        {
          this->push_back(vec[j].GetUint64());
        }
      }

      // W
      this->push_back(PUBLIC_KEY_W_LENGTH);

      this->push_back(PUBLIC_KEY_W_POINT_LENGTH);

      for (SizeType i = 0; i < W.Size(); i++) 
      {
        const Value& vec = W[i];
        if(!vec.IsArray())
          return cleanupAndFalse();
        if(!(vec.Size() == SizeType(PUBLIC_KEY_W_POINT_LENGTH)))
          return cleanupAndFalse();

        for(SizeType j = 0; j < vec.Size(); j++)
        {
          this->push_back(vec[j].GetUint64());
        }
      }

      // Make sure the final length is good
      if(!(this->size() == PUBLIC_KEY_VECTOR_LENGTH)) 
        return cleanupAndFalse();

      return true;
    }


// Stolen from https://github.com/zeutro/openabe/blob/master/src/include/openabe/utils/zbytestring.h

    bool fromHex(std::string s) {
      if((s.find_first_not_of(HEX_CHARS) != std::string::npos) ||
              (s.size() % 2 != 0)) {
        return false;
      }

      if ( s.length() != PUBLIC_KEY_HEX_STRING_LENGTH)
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