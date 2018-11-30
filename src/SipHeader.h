/*
 * SipHeader.h
 *
 *  Created on: Nov 30, 2018
 *      Author: yhl
 */

#ifndef SRC_SIPHEADER_H_
#define SRC_SIPHEADER_H_
#include <iostream>
#include <sstream>
#include <string>
using namespace std;
//SIP From/To 头部
class CSipFromToHeader
{
public:
    CSipFromToHeader()
    {
    }
    ~CSipFromToHeader()
    {
    }
    void SetHeader(string addrCod, string addrI, string addrPor)
    {
        addrCode = addrCod;
        addrIp = addrI;
        addrPort = addrPor;
    }
    string GetFormatHeader()
    {
        std::stringstream stream;
        stream << "sip: " << addrCode << "@" << addrIp << ":" << addrPort;
        return stream.str();
    }
    //主机名称
    string GetCode()
    {
        std::stringstream stream;
        stream << addrCode;
        return stream.str();
    }
    //主机地址
    string GetAddr()
    {
        std::stringstream stream;
        stream << addrIp;
        return stream.str();
    }
    //端口
    string GetPort()
    {
        std::stringstream stream;
        stream << addrPort;
        return stream.str();
    }

private:
    string addrCode;
    string addrIp;
    string addrPort;
};

//SIP Contract头部
class CContractHeader: public CSipFromToHeader
{
public:
    CContractHeader()
    {
    }
    ~CContractHeader()
    {
    }
    void SetContractHeader(string addrCod, string addrI, string addrPor)
    {
        SetHeader(addrCod, addrI, addrPor);
    }
    string GetContractFormatHeader()
    {

        std::stringstream stream;
        stream << "<sip:" << GetCode() << "@" << GetAddr() << ":" << GetPort()
                << ">";
        return stream.str();
    }
};



#endif /* SRC_SIPHEADER_H_ */
