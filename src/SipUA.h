#ifndef SIPUA_H_
#define SIPUA_H_
#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_port.h>

#include <eXosip2/eXosip.h>
#include <eXosip2/eX_setup.h>
#include <eXosip2/eX_register.h>
#include <eXosip2/eX_options.h>
#include <eXosip2/eX_message.h>

int cy_parse_catalog(eXosip_t *context_eXosip, char* p_xml_body,char* sn,char* devid);

int cy_parse_devinfo(eXosip_t *context_eXosip, char* p_xml_body,char* sn,char* devid);

int cy_parse_devstatus(eXosip_t *context_eXosip, char* p_xml_body,char* sn,char* devid);

#endif /* SIPUA_H_ */
