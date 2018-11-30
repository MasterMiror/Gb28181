/*
 * SipUA.cpp
 *
 *  Created on: Nov 30, 2018
 *      Author: yhl
 */
#include <iostream>
#include "SipUA.h"

using namespace std;

int cy_parse_catalog(eXosip_t *context_eXosip, char* p_xml_body,char* sn,char* devid)
{
	cout << "Catalog" << endl;
	return 0;
}

int cy_parse_devinfo(eXosip_t *context_eXosip, char* p_xml_body,char* sn,char* devid)
{
	cout << "DeviceInfo" << endl;
	return 0;
}

int cy_parse_devstatus(eXosip_t *context_eXosip, char* p_xml_body,char* sn,char* devid)
{
	cout << "DeviceStatus" << endl;
	return 0;
}


