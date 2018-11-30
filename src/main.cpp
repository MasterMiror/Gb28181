/*
 ===============================================================
 GBT28181 基于eXosip2,osip库实现注册UAC功能
 作者：程序人生
 博客地址：http://blog.csdn.net/hiwubihe
 QQ：1269122125
 注：请尊重原作者劳动成果，仅供学习使用，请勿盗用，违者必究！
 ================================================================
 */

#include <iostream>
#include <string>

#include <osipparser2/osip_message.h>
#include <osipparser2/osip_parser.h>
#include <osipparser2/osip_port.h>

#include <eXosip2/eXosip.h>
#include <eXosip2/eX_setup.h>
#include <eXosip2/eX_register.h>
#include <eXosip2/eX_options.h>
#include <eXosip2/eX_message.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "SipUA.h"
#include "SipHeader.h"

using namespace std;

//本地监听IP
#define LISTEN_ADDR ("192.168.87.171")
//本地监听端口
#define UACPORT ("5060")
#define UACPORTINT (5060)
//本UAC地址编码
#define UACCODE ("100110000201000000")
//本地UAC密码
#define UACPWD ("12345678")
//本UAS地址编码
#define UASCODE ("12010102002000000002")
//远程UAS IP
#define UASADDR ("192.168.87.15")
//远程UAS 端口
#define UASPORT ("5060")
//超时
#define EXPIS 300

//当前服务状态 1 已经注册 0 未注册
static int iCurrentStatus;
//注册成功HANDLE
static int iHandle = -1;

eXosip_t *context_eXosip;


//发送注册信息
int SendRegister(eXosip_t * osipEventPtr, int& registerId, CSipFromToHeader &from, CSipFromToHeader &to,
        CContractHeader &contact, const string& userName, const string& pwd,
        const int expires, int iType)
{
    cout << "=============================================" << endl;
    if (iType == 0)
    {
        cout << "注册请求信息：" << endl;
    }
    else if (iType == 1)
    {
        cout << "刷新注册信息：" << endl;
    }
    else
    {
        cout << "注销信息:" << endl;
    }
    cout << "registerId " << registerId << endl;
    cout << "from " << from.GetFormatHeader() << endl;
    cout << "to " << to.GetFormatHeader() << endl;
    cout << "contact" << contact.GetContractFormatHeader() << endl;
    cout << "userName" << userName << endl;
    cout << "pwd" << pwd << endl;
    cout << "expires" << expires << endl;
    cout << "=============================================" << endl;
    //服务器注册
    static osip_message_t *regMsg = 0;
    int ret;

    ::eXosip_add_authentication_info(osipEventPtr, userName.c_str(), userName.c_str(),
            pwd.c_str(), "MD5", NULL);
    eXosip_lock(osipEventPtr);
    //发送注册信息 401响应由eXosip2库自动发送
    if (0 == registerId)
    {
        // 注册消息的初始化
//        registerId = ::eXosip_register_build_initial_register(
//        		osipEventPtr,
//                from.GetFormatHeader().c_str(), to.GetFormatHeader().c_str(),
//                contact.GetContractFormatHeader().c_str(), expires, &regMsg);
        registerId = ::eXosip_register_build_initial_register(
               		   osipEventPtr,
                       from.GetFormatHeader().c_str(), to.GetFormatHeader().c_str(),
                       NULL, expires, &regMsg);
        if (registerId <= 0)
        {
            return -1;
        }
    }
    else
    {
        // 构建注册消息
        ret = ::eXosip_register_build_register(osipEventPtr, registerId, expires, &regMsg);
        if (ret != OSIP_SUCCESS)
        {
            return ret;
        }
        //添加注销原因
        if (expires == 0)
        {
            osip_contact_t *contact = NULL;
            char tmp[128];

            osip_message_get_contact(regMsg, 0, &contact);
            {
                sprintf(tmp, "<sip:%s@%s:%s>;expires=0",
                        contact->url->username, contact->url->host,
                        contact->url->port);
            }
            //osip_contact_free(contact);
            //reset contact header
            osip_list_remove(&regMsg->contacts, 0);
            osip_message_set_contact(regMsg, tmp);
            osip_message_set_header(regMsg, "Logout-Reason", "logout");
        }
    }
    // 发送注册消息
    ret = ::eXosip_register_send_register(osipEventPtr, registerId, regMsg);
    if (ret != OSIP_SUCCESS)
    {
        registerId = 0;
    }eXosip_unlock(osipEventPtr);

    return ret;
}

//注册
void Register(eXosip_t * osipEventPtr)
{
    if (iCurrentStatus == 1)
    {
        cout << "当前已经注册" << endl;
        return;
    }
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, LISTEN_ADDR, UACPORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UASCODE, UASADDR, UASPORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    int registerId = 0;
    if (0 > SendRegister(osipEventPtr, registerId, stFrom, stTo, stContract, UACCODE, UACPWD,
            3000, 0))
    {
        cout << "发送注册失败" << endl;
        return;
    }
    iCurrentStatus = 1;
    iHandle = registerId;
}
//刷新注册
void RefreshRegister(eXosip_t * osipEventPtr)
{
    if (iCurrentStatus == 0)
    {
        cout << "当前未注册，不允许刷新" << endl;
        return;
    }
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, LISTEN_ADDR, UACPORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UASCODE, UASADDR, UASPORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    if (0 > SendRegister(osipEventPtr, iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
            3000, 1))
    {
        cout << "发送刷新注册失败" << endl;
        return;
    }
}
//注销
void UnRegister(eXosip_t * osipEventPtr)
{
    if (iCurrentStatus == 0)
    {
        cout << "当前未注册，不允许注销" << endl;
        return;
    }
    CSipFromToHeader stFrom;
    stFrom.SetHeader(UACCODE, LISTEN_ADDR, UACPORT);
    CSipFromToHeader stTo;
    stTo.SetHeader(UASCODE, UASADDR, UASPORT);
    CContractHeader stContract;
    stContract.SetContractHeader(UACCODE, LISTEN_ADDR, UACPORT);
    //发送注册信息
    if (0 > SendRegister(osipEventPtr, iHandle, stFrom, stTo, stContract, UACCODE, UACPWD,
            0, 2))
    {
        cout << "发送注销失败" << endl;
        return;
    }
    iCurrentStatus = 0;
    iHandle = -1;
}
static void help()
{
    const char
            *b =
    "-------------------------------------------------------------------------------\n"
    "SIP Library test process - uac v 1.0 (June 13, 2014)\n\n"
    "SIP UAC端 注册,刷新注册,注销实现\n\n"
    "Author: 程序人生\n\n"
    "博客地址:http://blog.csdn.net/hiwubihe QQ:1269122125\n\n"
    "-------------------------------------------------------------------------------\n"
    "\n"
    "              0:Register\n"
    "              1:RefreshRegister\n"
    "              2:UnRegister\n"
    "              3:clear scream\n"
    "              4:exit\n"
    "-------------------------------------------------------------------------------\n"
    "\n";
    fprintf(stderr, b, strlen(b));
    cout << "please select method :";
}
//服务处理线程
void *serverHandle(void *pUser)
{
	eXosip_t * osipEventPtr = (eXosip_t *) pUser;
    sleep(3);
    help();
    char ch = getchar();
    getchar();
    while (1)
    {
        switch (ch)
        {
        case '0':
            //注册
            Register(osipEventPtr);
            break;
        case '1':
            //刷新注册
            RefreshRegister(osipEventPtr);
            break;
        case '2':
            //注销
            UnRegister(osipEventPtr);
            break;
        case '3':
            if (system("clear") < 0)
            {
                cout << "clear scream error" << endl;
                exit(1);
            }
            break;
        case '4':
            cout << "exit sipserver......" << endl;
            getchar();
            exit(0);
        default:
            cout << "select error" << endl;
            break;
        }
        cout << "press any key to continue......" << endl;
        getchar();
        help();
        ch = getchar();
        getchar();
    }
    return NULL;
}

// 打印事件消息
void cy_eXosip_printEvent(eXosip_event_t *p_event)
{
	printf("\r\n##############################################################\r\n");
	switch(p_event->type)
	{
		//case EXOSIP_REGISTRATION_NEW:
		//	printf("EXOSIP_REGISTRATION_NEW\r\n");
		//	break;
		case EXOSIP_REGISTRATION_SUCCESS:
			printf("EXOSIP_REGISTRATION_SUCCESS\r\n");
			break;
		case EXOSIP_REGISTRATION_FAILURE:
			printf("EXOSIP_REGISTRATION_FAILURE\r\n");
			break;
		//case EXOSIP_REGISTRATION_REFRESHED:
		//	printf("EXOSIP_REGISTRATION_REFRESHED\r\n");
		//	break;
		//case EXOSIP_REGISTRATION_TERMINATED:
		//	printf("EXOSIP_REGISTRATION_TERMINATED\r\n");
		//	break;
		case EXOSIP_CALL_INVITE:
			printf("EXOSIP_CALL_INVITE\r\n");
			break;
		case EXOSIP_CALL_REINVITE:
			printf("EXOSIP_CALL_REINVITE\r\n");
			break;
		case EXOSIP_CALL_NOANSWER:
			printf("EXOSIP_CALL_NOANSWER\r\n");
			break;
		case EXOSIP_CALL_PROCEEDING:
			printf("EXOSIP_CALL_PROCEEDING\r\n");
			break;
		case EXOSIP_CALL_RINGING:
			printf("EXOSIP_CALL_RINGING\r\n");
			break;
		case EXOSIP_CALL_ANSWERED:
			printf("EXOSIP_CALL_ANSWERED\r\n");
			break;
		case EXOSIP_CALL_REDIRECTED:
			printf("EXOSIP_CALL_REDIRECTED\r\n");
			break;
		case EXOSIP_CALL_REQUESTFAILURE:
			printf("EXOSIP_CALL_REQUESTFAILURE\r\n");
			break;
		case EXOSIP_CALL_SERVERFAILURE:
			printf("EXOSIP_CALL_SERVERFAILURE\r\n");
			break;
		case EXOSIP_CALL_GLOBALFAILURE:
			printf("EXOSIP_CALL_GLOBALFAILURE\r\n");
			break;
		case EXOSIP_CALL_ACK:
			printf("EXOSIP_CALL_ACK\r\n");
			break;
		case EXOSIP_CALL_CANCELLED:
			printf("EXOSIP_CALL_CANCELLED\r\n");
			break;
		//case EXOSIP_CALL_TIMEOUT:
		//	printf("EXOSIP_CALL_TIMEOUT\r\n");
		//	break;
		case EXOSIP_CALL_MESSAGE_NEW:
			printf("EXOSIP_CALL_MESSAGE_NEW\r\n");
			break;
		case EXOSIP_CALL_MESSAGE_PROCEEDING:
			printf("EXOSIP_CALL_MESSAGE_PROCEEDING\r\n");
			break;
		case EXOSIP_CALL_MESSAGE_ANSWERED:
			printf("EXOSIP_CALL_MESSAGE_ANSWERED\r\n");
			break;
		case EXOSIP_CALL_MESSAGE_REDIRECTED:
			printf("EXOSIP_CALL_MESSAGE_REDIRECTED\r\n");
			break;
		case EXOSIP_CALL_MESSAGE_REQUESTFAILURE:
			printf("EXOSIP_CALL_MESSAGE_REQUESTFAILURE\r\n");
			break;
		case EXOSIP_CALL_MESSAGE_SERVERFAILURE:
			printf("EXOSIP_CALL_MESSAGE_SERVERFAILURE\r\n");
			break;
		case EXOSIP_CALL_MESSAGE_GLOBALFAILURE:
			printf("EXOSIP_CALL_MESSAGE_GLOBALFAILURE\r\n");
			break;
		case EXOSIP_CALL_CLOSED:
			printf("EXOSIP_CALL_CLOSED\r\n");
			break;
		case EXOSIP_CALL_RELEASED:
			printf("EXOSIP_CALL_RELEASED\r\n");
			break;
		case EXOSIP_MESSAGE_NEW:
			printf("EXOSIP_MESSAGE_NEW\r\n");
			break;
		case EXOSIP_MESSAGE_PROCEEDING:
			printf("EXOSIP_MESSAGE_PROCEEDING\r\n");
			break;
		case EXOSIP_MESSAGE_ANSWERED:
			printf("EXOSIP_MESSAGE_ANSWERED\r\n");
			break;
		case EXOSIP_MESSAGE_REDIRECTED:
			printf("EXOSIP_MESSAGE_REDIRECTED\r\n");
			break;
		case EXOSIP_MESSAGE_REQUESTFAILURE:
			printf("EXOSIP_MESSAGE_REQUESTFAILURE\r\n");
			break;
		case EXOSIP_MESSAGE_SERVERFAILURE:
			printf("EXOSIP_MESSAGE_SERVERFAILURE\r\n");
			break;
		case EXOSIP_MESSAGE_GLOBALFAILURE:
			printf("EXOSIP_MESSAGE_GLOBALFAILURE\r\n");
			break;
		//case EXOSIP_SUBSCRIPTION_UPDATE:
		//	printf("EXOSIP_SUBSCRIPTION_UPDATE\r\n");
		//	break;
		//case EXOSIP_SUBSCRIPTION_CLOSED:
		//	printf("EXOSIP_SUBSCRIPTION_CLOSED\r\n");
		//	break;
		case EXOSIP_SUBSCRIPTION_NOANSWER:
			printf("EXOSIP_SUBSCRIPTION_NOANSWER\r\n");
			break;
		case EXOSIP_SUBSCRIPTION_PROCEEDING:
			printf("EXOSIP_SUBSCRIPTION_PROCEEDING\r\n");
			break;
		case EXOSIP_SUBSCRIPTION_ANSWERED:
			printf("EXOSIP_SUBSCRIPTION_ANSWERED\r\n");
			break;
		case EXOSIP_SUBSCRIPTION_REDIRECTED:
			printf("EXOSIP_SUBSCRIPTION_REDIRECTED\r\n");
			break;
		case EXOSIP_SUBSCRIPTION_REQUESTFAILURE:
			printf("EXOSIP_SUBSCRIPTION_REQUESTFAILURE\r\n");
			break;
		case EXOSIP_SUBSCRIPTION_SERVERFAILURE:
			printf("EXOSIP_SUBSCRIPTION_SERVERFAILURE\r\n");
			break;
		case EXOSIP_SUBSCRIPTION_GLOBALFAILURE:
			printf("EXOSIP_SUBSCRIPTION_GLOBALFAILURE\r\n");
			break;
		case EXOSIP_SUBSCRIPTION_NOTIFY:
			printf("EXOSIP_SUBSCRIPTION_NOTIFY\r\n");
			break;
		//case EXOSIP_SUBSCRIPTION_RELEASED:
		//	printf("EXOSIP_SUBSCRIPTION_RELEASED\r\n");
		//	break;
		case EXOSIP_IN_SUBSCRIPTION_NEW:
			printf("EXOSIP_IN_SUBSCRIPTION_NEW\r\n");
			break;
		//case EXOSIP_IN_SUBSCRIPTION_RELEASED:
		//	printf("EXOSIP_IN_SUBSCRIPTION_RELEASED\r\n");
		//	break;
		case EXOSIP_NOTIFICATION_NOANSWER:
			printf("EXOSIP_NOTIFICATION_NOANSWER\r\n");
			break;
		case EXOSIP_NOTIFICATION_PROCEEDING:
			printf("EXOSIP_NOTIFICATION_PROCEEDING\r\n");
			break;
		case EXOSIP_NOTIFICATION_ANSWERED:
			printf("EXOSIP_NOTIFICATION_ANSWERED\r\n");
			break;
		case EXOSIP_NOTIFICATION_REDIRECTED:
			printf("EXOSIP_NOTIFICATION_REDIRECTED\r\n");
			break;
		case EXOSIP_NOTIFICATION_REQUESTFAILURE:
			printf("EXOSIP_NOTIFICATION_REQUESTFAILURE\r\n");
			break;
		case EXOSIP_NOTIFICATION_SERVERFAILURE:
			printf("EXOSIP_NOTIFICATION_SERVERFAILURE\r\n");
			break;
		case EXOSIP_NOTIFICATION_GLOBALFAILURE:
			printf("EXOSIP_NOTIFICATION_GLOBALFAILURE\r\n");
			break;
		case EXOSIP_EVENT_COUNT:
			printf("EXOSIP_EVENT_COUNT\r\n");
			break;
		default:
			printf("..................\r\n");
			break;
	}
}

int cy_eXosip_paraseMsg(eXosip_event_t *p_event){
	osip_body_t *p_rqt_body = NULL;
	char *p_xml_body  = NULL;
	char *p_str_begin = NULL;
	char *p_str_end   = NULL;
	char xml_cmd_type[64];
	char xml_cmd_sn[64];
	char xml_device_id[64];
	int ret = 0;


	osip_message_get_body(p_event->request, 0, &p_rqt_body);/*获取接收到请求的XML消息体*/
	if(NULL == p_rqt_body)
	{
		printf("osip_message_get_body null!\r\n");
		return 0;
	}
	p_xml_body = p_rqt_body->body;
	printf("osip_message_get_body success!\r\n");

	printf("**********CMD START**********\r\n");
	p_str_begin = strstr(p_xml_body, "<CmdType>");
	p_str_end   = strstr(p_xml_body, "</CmdType>");
	ret =  p_str_end-p_str_begin-9;
	memcpy(xml_cmd_type,p_str_begin+9, ret);
	xml_cmd_type[ret] = 0;
	printf("<CmdType>:%s\r\n", xml_cmd_type);

	p_str_begin = strstr(p_xml_body, "<SN>");
	p_str_end   = strstr(p_xml_body, "</SN>");
	ret =  p_str_end-p_str_begin-4;
	memcpy(xml_cmd_sn, p_str_begin+4,ret);
	xml_cmd_sn[ret] = 0;
	printf("<SN>:%s\r\n", xml_cmd_sn);

	p_str_begin = strstr(p_xml_body, "<DeviceID>");
	p_str_end   = strstr(p_xml_body, "</DeviceID>");
	ret = p_str_end-p_str_begin-10;
	memcpy(xml_device_id, p_str_begin+10, ret);
	xml_device_id[ret] = 0;
	printf("<DeviceID>:%s\r\n", xml_device_id);
	printf("***********CMD END***********\r\n");

	if(0 == strcmp(xml_cmd_type, "Catalog"))
	{
		cy_parse_catalog(context_eXosip, p_xml_body,xml_cmd_sn,xml_device_id);

	}
	else if(0 == strcmp(xml_cmd_type, "DeviceInfo"))
	{
		cy_parse_devinfo(context_eXosip, p_xml_body,xml_cmd_sn,xml_device_id);

	}else if(0 == strcmp(xml_cmd_type, "DeviceStatus"))
	{
		cy_parse_devstatus(context_eXosip, p_xml_body,xml_cmd_sn,xml_device_id);

	}
	else
	{
		printf("gb : unknown msg\r\n");
	}

	return 0;
}

//事件处理线程
void *eventHandle(void *pEvent)
{
    eXosip_event_t* osipEventPtr = (eXosip_event_t*) pEvent;
    switch (osipEventPtr->type)
    {
    //需要继续验证REGISTER是什么类型
    case EXOSIP_REGISTRATION_SUCCESS:
    case EXOSIP_REGISTRATION_FAILURE:
    {
        cout<<"收到状态码:"<<osipEventPtr->response->status_code<<"报文"<<endl;
        if(osipEventPtr->response->status_code == 401)
        {
            cout<<"发送鉴权报文"<<endl;
        }
        else if(osipEventPtr->response->status_code == 200)
        {
            cout<<"接收成功"<<endl;
        }
        else
        {}
    }
        break;

    case EXOSIP_MESSAGE_NEW:
    {
    	cout << "注册成功，接送到message消息" << endl;
    	cy_eXosip_paraseMsg(osipEventPtr);
    }
    break;
    default:
        cout << "The sip event type that not be precessed.the event "
            "type is : " << osipEventPtr->type << endl;
        break;
    }
    eXosip_event_free(osipEventPtr);
    return NULL;
}

int main()
{

    iCurrentStatus = 0;
    //库处理结果
    int result = OSIP_SUCCESS;

    context_eXosip = eXosip_malloc();
    //初始化库
    if (OSIP_SUCCESS != (result = eXosip_init(context_eXosip)))
    {
        printf("eXosip_init failure.\n");
        return 1;
    }
    cout << "eXosip_init success." << endl;
    eXosip_set_user_agent(context_eXosip, NULL);
    //监听
    if (OSIP_SUCCESS != eXosip_listen_addr(context_eXosip, IPPROTO_UDP, NULL, UACPORTINT,
            AF_INET, 0))
    {
        printf("eXosip_listen_addr failure.\n");
        return 1;
    }
    //设置监听网卡
    if (OSIP_SUCCESS != eXosip_set_option(
    		context_eXosip,
			EXOSIP_OPT_SET_IPV4_FOR_GATEWAY,
            LISTEN_ADDR))
    {
        return -1;
    }
    //开启服务线程
    pthread_t pthser;
    if (0 != pthread_create(&pthser, NULL, serverHandle, (void*)context_eXosip))
    {
        printf("创建主服务失败\n");
        return -1;
    }
    //事件用于等待
    eXosip_event_t* osipEventPtr = NULL;
    //开启事件循环
    while (true)
    {
        //等待事件 0的单位是秒，500是毫秒
        osipEventPtr = ::eXosip_event_wait(context_eXosip, 0, 0);
        //处理eXosip库默认处理
        {
            usleep(500 * 1000);
            eXosip_lock(context_eXosip);
            //一般处理401/407采用库默认处理
            eXosip_default_action(context_eXosip, osipEventPtr);
            //eXosip_automatic_action(context_eXosip);
            eXosip_unlock(context_eXosip);
        }
        //事件空继续等待
        if (NULL == osipEventPtr)
        {
            continue;
        }
        cy_eXosip_printEvent(osipEventPtr);
        //开启线程处理事件并在事件处理完毕将事件指针释放
        pthread_t pth;
        if (0 != pthread_create(&pth, NULL, eventHandle, (void*) osipEventPtr))
        {
            printf("创建线程处理事件失败\n");
            continue;
        }
        osipEventPtr = NULL;
    }
}
