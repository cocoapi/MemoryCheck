#include <iostream>
#include <random>
#include <ctime>
#include <windows.h>
#include <atltime.h> //CTime
#include <atlstr.h>	//CString
using namespace std;

int main() {
	char command[30];
	int count = 0, error;
	cout << "input new ip_address or connect:00000 or start default" << endl
		<< "> ";
	cin >> command;
	cout << "attach" << endl << endl
		<< " PID:[15003]executed" << endl << endl
		<< "connectting";
	for (int i = 0; i < 5; i++) {
		Sleep(1000);
		cout << '.';
	}
	Sleep(5000);
	srand(time(NULL));
	cout << endl << endl << "process generated" << endl << endl;
	error = rand() % 5 + 1;
	while (1) {
		cout << "Please input command(c: continue d: dump memory p: pause" << endl
			<< "> ";
		cin >> command;
		switch (command[0]) {
		case 'c': 
		case 'C':
			cout << "continue" << endl << endl;
			break;
		case 'd':
		case 'D':
			cout << "dump memory" << endl << endl;
			count++;
			break;
		case 'p':
		case 'P':
			cout << "pause process" << endl << endl;
			break;
		default:
			break;
		}
		if (error == count) {
			CTime time = GetCurrentTime();
			CString tStr = time.Format(_T("%Y-%m-%d-%H-%M-%S"));
			cout << "Error detected!!" << endl
				<< tStr << "@ Memory." << count << endl
				<< "Create error log on 'error.log'" << endl;
			error = rand() % 5 + 1;
		}
	}
	return 0;
}