#ifndef __PUBLICPARAMS_H__
#define __PUBLICPARAMS_H__


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
#define PUBLIC_PARAMS_VECTOR_LENGTH 196
#define PUBLIC_PARAMS_HEX_STRING_LENGTH PUBLIC_PARAMS_VECTOR_LENGTH*2

#define PUBLIC_PARAMS_G1_LENGTH 65
#define PUBLIC_PARAMS_G2_LENGTH 129

#define PUBLIC_PARAMS_BPGENS_LENGTH 2


using namespace rapidjson;

class PublicParams : public std::vector<uint8_t> {

  
  public:

    std::string toJson() {

      Document json;
      // allocator for memory management
      Document::AllocatorType& allocator = json.GetAllocator();

      // define the document as an object rather than an array
      json.SetObject();

      if( PUBLIC_PARAMS_VECTOR_LENGTH != this->size())
        return("{}");

      // iterator we are going to be using the whole time
      std::vector<uint8_t>::iterator it = this->begin();

      Value cl_mpk(kObjectType);

      // Double check the G1 length
      if( PUBLIC_PARAMS_G1_LENGTH != *it )
        return("{}");
      it++;

      Value g1(kArrayType);
      for( int j = 0; j< PUBLIC_PARAMS_G1_LENGTH; j++) 
      { 
        g1.PushBack(*it, allocator);
        it++;
      }

      // Double check the Y length
      if( PUBLIC_PARAMS_G2_LENGTH != *it )
        return("{}");
      it++;

      Value g2(kArrayType);
      for( int j = 0; j< PUBLIC_PARAMS_G2_LENGTH; j++) 
      { 
        g2.PushBack(*it, allocator);
        it++;
      }

      cl_mpk.AddMember("g1", g1, allocator);
      cl_mpk.AddMember("g2", g2, allocator);
      json.AddMember("cl_mpk", cl_mpk, allocator);

      //Adding in the defaults TODO FIGURE OUT IS THESE ARE CONSTANT

      json.AddMember("l", 4, allocator);

      Value bp_gens(kArrayType);
      bp_gens.PushBack(64, allocator).PushBack(1, allocator);
      json.AddMember("bp_gens", bp_gens, allocator);

      json.AddMember("range_proof_bits",32, allocator);
      json.AddMember("extra_verify", false, allocator);

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
      if(!json.HasMember("cl_mpk"))
        return false;

      // Defaults.  We might be able to ignore?

      if(!json.HasMember("l"))
        return false;
      if(!json.HasMember("bp_gens"))
        return false;
      if(!json.HasMember("range_proof_bits"))
        return false;
      if(!json.HasMember("extra_verify"))
        return false;

      const Value& cl_mpk = json["cl_mpk"];

      if(!cl_mpk.IsObject())
        return false;

      if(!cl_mpk.HasMember("g1"))
        return false;
      if(!cl_mpk.HasMember("g2"))
        return false;

      const Value& g1 = cl_mpk["g1"];
      const Value& g2 = cl_mpk["g2"];

      if(!g1.IsArray())
        return false;      
      if(!g2.IsArray())
        return false;

      if(!(g1.Size() == SizeType(PUBLIC_PARAMS_G1_LENGTH)))
        return false;  
      if(!(g2.Size() == SizeType(PUBLIC_PARAMS_G2_LENGTH)))
        return false;

      // Add the header information
      // From here on out, make sure to call cleanupAndFalse() instead of false
      
      // g1
      this->push_back(PUBLIC_PARAMS_G1_LENGTH);

      for(SizeType j = 0; j < g1.Size(); j++)
        this->push_back(g1[j].GetUint64());

      // Y
      this->push_back(PUBLIC_PARAMS_G2_LENGTH);

      for(SizeType j = 0; j < g2.Size(); j++)
        this->push_back(g2[j].GetUint64());      

      // Make sure the final length is good
      if(!(this->size() == PUBLIC_PARAMS_VECTOR_LENGTH)) 
        return cleanupAndFalse();

      return true;
    }


// Stolen from https://github.com/zeutro/openabe/blob/master/src/include/openabe/utils/zbytestring.h

    bool fromHex(std::string s) {
      if((s.find_first_not_of(HEX_CHARS) != std::string::npos) ||
              (s.size() % 2 != 0)) {
        return false;
      }

      if ( s.length() != PUBLIC_PARAMS_HEX_STRING_LENGTH)
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