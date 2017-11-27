#include <iostream>
#include <fstream>
#include <bitset>	//bitset
#include <windows.h>
#include <tchar.h>
#include <cstdio> 
#include <strsafe.h> 
#include <process.h> //Thread
#include <atltime.h> //CTime
#include <atlstr.h>	//CString
using namespace std;


#define BUFSIZE 256 //pipe's max buffer size
#define THREADNUM 6 //Thread's quantity

//handler for child process's STDIN
HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hInputFile = NULL;

//parameters for thread
typedef struct tagTREADPARAMS {
	ifstream *fin0;
	ifstream *fin1;
	bool *Error;
	int *filenum;
} THREADPAPAMS;

void CreateChildProcess(void);	//creating childprocess
void WriteToPipe(void);			//let child process read commands
void ErrorExit(PTSTR);
void memCheck(void* thParam);	//checking dumped memory using thread

int main() {
	ofstream com("command.txt", ios::trunc);
	com.close();
	SECURITY_ATTRIBUTES saAttr;	//windows default Security attribute
	bool front = true, dumped = false;			//for change dumped memory name 
	int counter = 0;			//to count how many dumped

	// Set the bInheritHandle flag so pipe handles are inherited. 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	

	// Create a pipe for the child process's STDIN. 
	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
		ErrorExit(TEXT("Stdin CreatePipe"));

	// Ensure the write handle to the pipe for STDIN is not inherited. 
	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))	
		ErrorExit(TEXT("Stdin SetHandleInformation"));

	// Create the child process. 
	CreateChildProcess();

	// Get a handle to an input file for the parent. 
	// This example assumes a plain text file and uses string output to verify data flow. 
	g_hInputFile = CreateFile(
		"command.txt",
		GENERIC_READ,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_READONLY,
		NULL);

	// Write to the pipe that is the standard input for a child process. 
	// Data is written to the pipe's buffers, so it is not necessary to wait
	// until the child process is running before writing data.
	char ipport[50];
	ZeroMemory(ipport, 50);
	cout << "input remote ip and port: (<IPADDR>:<PORT>)" << endl << "> ";
	cin >> ipport;
	com.open("command.txt", ios::app);
	com << "target remote ";
	if (ipport[0] != ':' && strlen(ipport) < 6) {
		com << ':' << ipport;
	}else{
		com << ipport;
	}
	com << endl << "c" << endl;
	com.close();
	WriteToPipe(); //child reads on pipe
	while (1) {
		dumped = false;
		char mainCommand = 0;
		cout << "Command Input: (c:continue d:dump  s:attack and dump p:pause q: quit" << endl << "> ";
		cin >> mainCommand;
		ofstream com("command.txt", ios::app);
		switch (mainCommand) {
		case 'c':
		case 'C':
			com << "c" << endl;
			break;
		case 'D':
		case 'd':
			if (front) {
				com << "^C" << endl
					<< "dump memory /dump/memory.0 0x60008000 0x60808000" << endl
					<< "dump memory /dump/memory.1 0x60808000 0x60f08000" << endl
					<< "dump memory /dump/memory.2 0x60f08000 0x61808000" << endl
					<< "dump memory /dump/memory.3 0x61808000 0x61f08000" << endl
					<< "dump memory /dump/memory.4 0x61f08000 0x62808000" << endl
					<< "dump memory /dump/memory.5 0x62808000 0x62ae2000" << endl
					<< "c" << endl;
				front = false;
			}
			else {
				com << "^C" << endl
					<< "dump memory /dump/memory.00 0x60008000 0x60808000" << endl
					<< "dump memory /dump/memory.10 0x60808000 0x60f08000" << endl
					<< "dump memory /dump/memory.20 0x60f08000 0x61808000" << endl
					<< "dump memory /dump/memory.30 0x61808000 0x61f08000" << endl
					<< "dump memory /dump/memory.40 0x61f08000 0x62808000" << endl
					<< "dump memory /dump/memory.50 0x62808000 0x62ae2000" << endl
					<< "c" << endl;
				front = true;
			}
			counter++;
			dumped = true;
			break;
		case 'S':
		case 's':
			if (front) {
				com << "^C" << endl
					<< "set *((int*)0x604a6ad4) = 604110849" << endl
					<< "dump memory /dump/memory.0 0x60008000 0x60808000" << endl
					<< "dump memory /dump/memory.1 0x60808000 0x60f08000" << endl
					<< "dump memory /dump/memory.2 0x60f08000 0x61808000" << endl
					<< "dump memory /dump/memory.3 0x61808000 0x61f08000" << endl
					<< "dump memory /dump/memory.4 0x61f08000 0x62808000" << endl
					<< "dump memory /dump/memory.5 0x62808000 0x62ae2000" << endl
					<< "c" << endl;
				front = false;
			}
			else {
				com << "^C" << endl
					<< "set *((int*)0x604a6ad4) = 604110849" << endl
					<< "dump memory /dump/memory.00 0x60008000 0x60808000" << endl
					<< "dump memory /dump/memory.10 0x60808000 0x60f08000" << endl
					<< "dump memory /dump/memory.20 0x60f08000 0x61808000" << endl
					<< "dump memory /dump/memory.30 0x61808000 0x61f08000" << endl
					<< "dump memory /dump/memory.40 0x61f08000 0x62808000" << endl
					<< "dump memory /dump/memory.50 0x62808000 0x62ae2000" << endl
					<< "c" << endl;
				front = true;
			}
			dumped = true;
			counter++;
			break;
		case 'P':
		case 'p':
			com << "^C" << endl;
			break;
		case 'Q':
		case 'q':
			if (!CloseHandle(g_hChildStd_IN_Wr))
				ErrorExit(TEXT("StdInWr CloseHandle"));
			com.close();
			return 0;
		default:
			break;
		}
		com.close();
		WriteToPipe(); //child reads on pipe
		Sleep(10000);
		if (counter >= 2 && dumped) {
			string path1;
			string path2;
			if (front == false) {
				path1 = "./dump/memory.0";
				path2 = "./dump/memory.00";
			}
			else {
				path1 = "./dump/memory.00";
				path2 = "./dump/memory.0";
			}
			ifstream fin[THREADNUM * 2];
			bool Error[THREADNUM];
			bool fileCheck = false;
			tagTREADPARAMS *tParam[THREADNUM];
			HANDLE hThread[6];
			for (int i = 0; i < THREADNUM; i++) {
				Error[i] = false;
				fin[i].open(path1, ios::binary);
				fin[i + THREADNUM].open(path2, ios::binary);
				if (!fin[i] || !fin[i + THREADNUM]) {
					fileCheck = false;
					break;
				}
				else {
					fileCheck = true;
				}
				path1[15]++;
				path2[15]++;
				tParam[i] = new tagTREADPARAMS;
				tParam[i]->Error = &(Error[i]);
				tParam[i]->fin0 = &fin[i];
				tParam[i]->fin1 = &fin[i + THREADNUM];
				tParam[i]->filenum = new int(i);
				hThread[i] = (HANDLE)_beginthread(memCheck, 0, (void*)tParam[i]);
			}
			if (fileCheck == true) {
				DWORD tEnd[THREADNUM];
				bool endCheck = false;
				while (!endCheck) {
					if (tEnd[0] != STILL_ACTIVE &&
						tEnd[1] != STILL_ACTIVE &&
						tEnd[2] != STILL_ACTIVE &&
						tEnd[3] != STILL_ACTIVE &&
						tEnd[4] != STILL_ACTIVE &&
						tEnd[5] != STILL_ACTIVE) {
						endCheck = true;
					}
					else {
						for (int i = 0; i < THREADNUM; i++) {
							GetExitCodeThread(hThread[i], &tEnd[i]);
						}
					}
				}
				for (int i = 0; i < THREADNUM; i++) {
					if (Error[i] == true) {
						ofstream fout("./log/error.log", ios::app);
						CTime time = GetCurrentTime();
						CString tStr = time.Format(_T("%Y-%m-%d-%H-%M-%S"));
						fout << tStr;
						if (front == true) {
							fout << " ./dump/memory." << i << 0 << endl;
						}
						else {
							fout << "./dump/memory." << i << endl;
						}
						fout.close();
					}
				}
			}
			else {
				cout << "memory dump fail!!" << endl;
			}
		}
	}
	return 0;
}
	
void CreateChildProcess()
// Create a child process that uses the previously created pipes for STDIN.
{
	TCHAR szCmdline[] = TEXT("./gdb/gdb6.exe");
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	siStartInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	// Create the child process. 

	bSuccess = CreateProcess(NULL,
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		CREATE_NO_WINDOW,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 

					   // If an error occurs, exit the application. 
	if (!bSuccess)
		ErrorExit(TEXT("CreateProcess"));
	else
	{
		// Close handles to the child process and its primary thread.
		// Some applications might keep these handles to monitor the status
		// of the child process, for example. 
		cout << "PID: " << piProcInfo.dwProcessId << "executed." << endl;
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
	}
}

void WriteToPipe(void)

// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{
	DWORD dwRead, dwWritten;
	CHAR chBuf[BUFSIZE];
	BOOL bSuccess = FALSE;

	if (g_hInputFile == INVALID_HANDLE_VALUE)
		ErrorExit(TEXT("CreateFile"));
	
	for (;;)
	{
		bSuccess = ReadFile(g_hInputFile, chBuf, BUFSIZE, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;

		bSuccess = WriteFile(g_hChildStd_IN_Wr, chBuf, dwRead, &dwWritten, NULL);
		if (!bSuccess) break;
	}
}

void ErrorExit(PTSTR lpszFunction)

// Format a readable error message, display a message box, 
// and exit from the application.
{
	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(1);
}

void memCheck(void *thParam) {
	tagTREADPARAMS *param = (tagTREADPARAMS*)thParam;
	ifstream *fin1 = param->fin0;
	ifstream *fin2 = param->fin1;
	if (fin1) {
		// get length of file:
		fin1->seekg(0, fin1->end);
		int length = fin1->tellg();
		fin1->seekg(0, fin1->beg);

		bool differ = false;
		char *buffer = new char[length];
		char *buffer2 = new char[length];

		bitset<8> x, y;
		// read data as a block:
		fin1->read(buffer, length);
		fin2->read(buffer2, length);
		for (int i = 0; i < length; i++) {
			x = buffer[i];
			y = buffer2[i];
			if (x != y) {
				differ = true;
			}
		}
		if (differ == true) {
			CTime t = GetCurrentTime();
			string fStr = "./log/error_";
			CString tStr = t.Format(_T("%Y-%m-%d-%H-%M-%S"));
			fStr.append(tStr);
			fStr.append(".");
			switch (*(param->filenum)) {
			case 0:
				fStr.append("0");
				break;
			case 1:
				fStr.append("1");
				break;
			case 2:
				fStr.append("2");
				break;
			case 3:
				fStr.append("3");
				break;
			case 4:
				fStr.append("4");
				break;
			case 5:
				fStr.append("5");
				break;
			}
			ofstream fout(fStr);
			fout << buffer;
		}
		delete[] buffer;
		delete[] buffer2;
	}
}
