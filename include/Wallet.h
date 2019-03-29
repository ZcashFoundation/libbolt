#ifndef __WALLET_H__
#define __WALLET_H__


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
#define WALLET_VECTOR_LENGTH 130
#define WALLET_HEX_STRING_LENGTH WALLET_VECTOR_LENGTH*2

#define WALLET_LENGTH 4
#define WALLET_POINT_LENGTH 32


using namespace rapidjson;

class Wallet : public std::vector<uint8_t> {

  
  public:

    std::string toJson() {

      Document json;
      // allocator for memory management
      Document::AllocatorType& allocator = json.GetAllocator();

      // define the document as an object rather than an array
      json.SetArray();

      if( WALLET_VECTOR_LENGTH != this->size())
        return("{}");

      // iterator we are going to be using the whole time
      std::vector<uint8_t>::iterator it = this->begin();

      // Double check the Wallet length
      if( WALLET_LENGTH != *it )
        return("{}");
      it++;

      // Double check the Wallet element length
      if( WALLET_POINT_LENGTH != *it )
        return("{}");
      it++;

      for( int i = 0; i< WALLET_LENGTH; i++)
      {
        Value point(kArrayType);
        for( int j = 0; j< WALLET_POINT_LENGTH; j++) 
        { 
          point.PushBack(*it, allocator);
          it++;
        }
        json.PushBack(point, allocator);
    }

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
      if(!json.IsArray())
        return false;

      if(!(json.Size() == SizeType(WALLET_LENGTH)))
        return false; 

      this->push_back(WALLET_LENGTH);
      this->push_back(WALLET_POINT_LENGTH);


      for( int i =0; i< WALLET_LENGTH; i++)
      {
        const Value& point = json[i];

        if(!point.IsArray())
          return false;

        if(!(point.Size() == SizeType(WALLET_POINT_LENGTH)))
          cleanupAndFalse();

        for(SizeType j = 0; j < point.Size(); j++)
          this->push_back(point[j].GetUint64());

      }

      // Make sure the final length is good
      if(!(this->size() == WALLET_VECTOR_LENGTH)) 
        return cleanupAndFalse();

      return true;
    }


// Stolen from https://github.com/zeutro/openabe/blob/master/src/include/openabe/utils/zbytestring.h

    bool fromHex(std::string s) {
      if((s.find_first_not_of(HEX_CHARS) != std::string::npos) ||
              (s.size() % 2 != 0)) {
        return false;
      }

      if ( s.length() != WALLET_HEX_STRING_LENGTH)
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