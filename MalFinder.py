import pefile
import sys
import requests
'''
Author: J0eBinary
X: https://twitter.com/j0e_Binary

This tool takes a PE file (e.g. *.exe) and checks if the Import Address Table (IAT) contains a suspicious function that is usually used in malware.


The process is done by checking if the function name is present at https://malapi.io/ .

If so, the tool returns the description of the function and what it is used for.

'''

#green,red, and yellow colors 
def printGreen(text): print("\033[92m{}\033[00m".format(text))
def printYellow(text): print("\033[93m{}\033[00m".format(text))
def printRed(text): print("\033[91m{}\033[00m".format(text))

#check if the number of parameters is 2 (the script and the PE file)
def usage():
	if len(sys.argv) == 2:
		return
	else:
		print("Usage : python3 MalFinder.py <PE FILE>")
		exit(-1)
#check if the file is a valid PE file
def peChecker(peFile):

	try:
		with open(peFile,"rb") as fileHandler:
			if fileHandler.read(2)==b"MZ":
				return
			else:
				print("The file is not a valid PE")
				exit(0)
	except FileNotFoundError:
		print("File not found....")
		exit(-1)

#print Banner
def banner():
	print(''''   _ _____     ______ _                        
  (_)  _  |    | ___ (_)                       
   _| |/' | ___| |_/ /_ _ __   __ _ _ __ _   _ 
  | |  /| |/ _ \\ ___ \\ | '_ \\ / _` | '__| | | |
  | \\ |_/ /  __/ |_/ / | | | | (_| | |  | |_| |
  | |\\___/ \\___\\____/|_|_| |_|\\_\\_,_|_|   \\__, |
 _/ |                                     __/ |
|__/                                     |___/ ''')
	print("X: https://twitter.com/j0e_Binary")
	print("=========================\n=========================")

#grab the function description by connecting to malapi.io
def malAPI_checker(functionToBeChecked):
		
	url = "https://malapi.io/winapi/"+functionToBeChecked
	try:
		response = requests.get(url).text
		index_of_socket = response.find(functionToBeChecked+' ')
		index_of_dot = response.find("\n",index_of_socket)
		result = response[index_of_socket:index_of_dot]
		printYellow(result)
	except:
		printRed("No Internet Connection.....")
		exit(-1)


def printEnumerationFunctions(functions_imports):
	if not functions_imports : return 
	printGreen("Functions used for Enumeration:")
	for i in functions_imports:
		printRed(i)
		malAPI_checker(i)


def printInejectionFunctions(functions_imports):
	if not functions_imports : return 
	printGreen("Functions used for Injection:")
	for i in functions_imports:
		printRed(i)
		malAPI_checker(i)

def printEvasionFunctions(functions_imports):
	if not functions_imports : return 
	printGreen("Functions used for Evasion:")
	for i in functions_imports:
		printRed(i)
		malAPI_checker(i)

def printSpyingFunctions(functions_imports):
	
	if not functions_imports : return 
	printGreen("Functions used for Spying:")
	for i in functions_imports:
		printRed(i)
		malAPI_checker(i)

def printInternetFunctions(functions_imports):
	
	if not functions_imports : return 
	printGreen("Functions used for Internet Connection:")
	for i in functions_imports:
		printRed(i)
		malAPI_checker(i)
def printAnti_DebuggingFunctions(functions_imports):
	
	if not functions_imports : return 
	printGreen("Functions used for Anti Debugging:")
	for i in functions_imports:
		printRed(i)
		malAPI_checker(i)


def printRansomwareFunctions(functions_imports):
	
	if not functions_imports : return 
	printGreen("Functions used for Encryption/Ransomwares:")
	for i in functions_imports:
		printRed(i)
		malAPI_checker(i)

EnumerationImports,InjectionImports,EvasionImports,SpyingImports,InternetImports,Anti_DebuggingImports,RansomwareImports = [],[],[],[],[],[],[]

#sus functions
Enumeration = ["CreateToolhelp32Snapshot","EnumDeviceDrivers","EnumProcesses","EnumProcessModules","EnumProcessModulesEx","FindFirstFileA","FindNextFileA","GetLogicalProcessorInformation","GetLogicalProcessorInformationEx","GetModuleBaseNameA","GetSystemDefaultLangId","GetVersionExA","GetWindowsDirectoryA","IsWoW64Process","Module32First","Module32Next","Process32First","Process32Next","ReadProcessMemory","Thread32First","Thread32Next","GetSystemDirectoryA","GetSystemTime","ReadFile","GetComputerNameA","VirtualQueryEx","GetProcessIdOfThread","GetProcessId","GetCurrentThread","GetCurrentThreadId","GetThreadId","GetThreadInformation","GetCurrentProcess","GetCurrentProcessId","SearchPathA","GetFileTime","GetFileAttributesA","LookupPrivilegeValueA","LookupAccountNameA","GetCurrentHwProfileA","GetUserNameA","RegEnumKeyExA","RegEnumValueA","RegQueryInfoKeyA","RegQueryMultipleValuesA","RegQueryValueExA","NtQueryDirectoryFile","NtQueryInformationProcess","NtQuerySystemEnvironmentValueEx","EnumDesktopWindows","EnumWindows","NetShareEnum","NetShareGetInfo","NetShareCheck","GetAdaptersInfo","PathFileExistsA","GetNativeSystemInfo","RtlGetVersion","GetIpNetTable","GetLogicalDrives","GetDriveTypeA","RegEnumKeyA","WNetEnumResourceA","WNetCloseEnum","FindFirstUrlCacheEntryA","FindNextUrlCacheEntryA","WNetAddConnection2A","WNetAddConnectionA","EnumResourceTypesA","EnumResourceTypesExA","GetThreadLocale","EnumSystemLocalesA"]

Injection =["CreateFileMappingA","CreateProcessA","CreateRemoteThread","CreateRemoteThreadEx","GetProcAddress","GetThreadContext","HeapCreate","LoadLibraryA","LoadLibraryExA","LocalAlloc","MapViewOfFile","MapViewOfFile2","MapViewOfFile3","MapViewOfFileEx","OpenThread","Process32First","Process32Next","QueueUserAPC","ReadProcessMemory","ResumeThread","SetProcessDEPPolicy","SetThreadContext","SuspendThread","Thread32First","Thread32Next","Toolhelp32ReadProcessMemory","VirtualAlloc","VirtualAllocEx","VirtualProtect","VirtualProtectEx","WriteProcessMemory","VirtualAllocExNuma","VirtualAlloc2","VirtualAlloc2FromApp","VirtualAllocFromApp","VirtualProtectFromApp","CreateThread","WaitForSingleObject","OpenProcess","OpenFileMappingA","GetProcessHeap","GetProcessHeaps","HeapAlloc","HeapReAlloc","GlobalAlloc","AdjustTokenPrivileges","CreateProcessAsUserA","OpenProcessToken","CreateProcessWithTokenW","NtAdjustPrivilegesToken","NtAllocateVirtualMemory","NtContinue","NtCreateProcess","NtCreateProcessEx","NtCreateSection","NtCreateThread","NtCreateThreadEx","NtCreateUserProcess","NtDuplicateObject","NtMapViewOfSection","NtOpenProcess","NtOpenThread","NtProtectVirtualMemory","NtQueueApcThread","NtQueueApcThreadEx","NtQueueApcThreadEx2","NtReadVirtualMemory","NtResumeThread","NtUnmapViewOfSection","NtWaitForMultipleObjects","NtWaitForSingleObject","NtWriteVirtualMemory","RtlCreateHeap","LdrLoadDll","RtlMoveMemory","RtlCopyMemory","SetPropA","WaitForSingleObjectEx","WaitForMultipleObjects","WaitForMultipleObjectsEx","KeInsertQueueApc","Wow64SetThreadContext","NtSuspendProcess","NtResumeProcess","DuplicateToken","NtReadVirtualMemoryEx","CreateProcessInternal","EnumSystemLocalesA","UuidFromStringA"]

Evasion = ["CreateFileMappingA","DeleteFileA","GetProcAddress","LoadLibraryA","LoadLibraryExA","LoadResource","SetEnvironmentVariableA","SetFileTime","Sleep","WaitForSingleObject","SetFileAttributesA","SleepEx","NtDelayExecution","NtWaitForMultipleObjects","NtWaitForSingleObject","CreateWindowExA","RegisterHotKey","timeSetEvent","IcmpSendEcho","WaitForSingleObjectEx","WaitForMultipleObjects","WaitForMultipleObjectsEx","SetWaitableTimer","CreateTimerQueueTimer","CreateWaitableTimer","SetWaitableTimer","SetTimer","Select","ImpersonateLoggedOnUser","SetThreadToken","DuplicateToken","SizeOfResource","LockResource","CreateProcessInternal","TimeGetTime","EnumSystemLocalesA","UuidFromStringA"]

Spying = ["AttachThreadInput","CallNextHookEx","GetAsyncKeyState","GetClipboardData","GetDC","GetDCEx","GetForegroundWindow","GetKeyboardState","GetKeyState","GetMessageA","GetRawInputData","GetWindowDC","MapVirtualKeyA","MapVirtualKeyExA","PeekMessageA","PostMessageA","PostThreadMessageA","RegisterHotKey","RegisterRawInputDevices","SendMessageA","SendMessageCallbackA","SendMessageTimeoutA","SendNotifyMessageA","SetWindowsHookExA","SetWinEventHook","UnhookWindowsHookEx","BitBlt","StretchBlt","GetKeynameTextA"]

Internet = ["WinExec","FtpPutFileA","HttpOpenRequestA","HttpSendRequestA","HttpSendRequestExA","InternetCloseHandle","InternetOpenA","InternetOpenUrlA","InternetReadFile","InternetReadFileExA","InternetWriteFile","URLDownloadToFile","URLDownloadToCacheFile","URLOpenBlockingStream","URLOpenStream","Accept","Bind","Connect","Gethostbyname","Inet_addr","Recv","Send","WSAStartup","Gethostname","Socket","WSACleanup","Listen","ShellExecuteA","ShellExecuteExA","DnsQuery_A","DnsQueryEx","WNetOpenEnumA","FindFirstUrlCacheEntryA","FindNextUrlCacheEntryA","InternetConnectA","InternetSetOptionA","WSASocketA","Closesocket","WSAIoctl","ioctlsocket","HttpAddRequestHeaders"]


Anti_Debugging = ["CreateToolhelp32Snapshot","GetLogicalProcessorInformation","GetLogicalProcessorInformationEx","GetTickCount","OutputDebugStringA","CheckRemoteDebuggerPresent","Sleep","GetSystemTime","GetComputerNameA","SleepEx","IsDebuggerPresent","GetUserNameA","NtQueryInformationProcess","ExitWindowsEx","FindWindowA","FindWindowExA","GetForegroundWindow","GetTickCount64","QueryPerformanceFrequency","QueryPerformanceCounter","GetNativeSystemInfo","RtlGetVersion","CountClipboardFormats"]

Ransomware = ["CryptAcquireContextA","EncryptFileA","CryptEncrypt","CryptDecrypt","CryptCreateHash","CryptHashData","CryptDeriveKey","CryptSetKeyParam","CryptGetHashParam","CryptSetKeyParam","CryptDestroyKey","CryptGenRandom","DecryptFileA","FlushEfsCache","GetLogicalDrives","GetDriveTypeA","CryptStringToBinary","CryptBinaryToString","CryptReleaseContext","CryptDestroyHash","EnumSystemLocalesA"]

usage()
peChecker(sys.argv[1])
banner()

file = pefile.PE(sys.argv[1])
for item in file.DIRECTORY_ENTRY_IMPORT:
	
	for imports_from_dll in item.imports:
		
		decodedFunctionName = (imports_from_dll.name.decode('utf-8'))
		if (decodedFunctionName in Enumeration):
	 		EnumerationImports.append(decodedFunctionName)
		if (decodedFunctionName in Injection):
			InjectionImports.append(decodedFunctionName)

		if (decodedFunctionName in Evasion):
			EvasionImports.append(decodedFunctionName)


		if (decodedFunctionName in Spying):
			SpyingImports.append(decodedFunctionName)


		if (decodedFunctionName in Internet):
			InternetImports.append(decodedFunctionName)


		if (decodedFunctionName in Anti_Debugging):
			Anti_DebuggingImports.append(decodedFunctionName)


		if (decodedFunctionName in Ransomware):
			RansomwareImports.append(decodedFunctionName)

printEnumerationFunctions(EnumerationImports)
printInejectionFunctions(InjectionImports)
printEvasionFunctions(EvasionImports)
printSpyingFunctions(SpyingImports)
printInternetFunctions(InternetImports)
printAnti_DebuggingFunctions(Anti_DebuggingImports)
printRansomwareFunctions(RansomwareImports)
