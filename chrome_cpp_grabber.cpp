#include <stdio.h>
#include <stdlib.h>
#include "sqlite3.h"
#include <windows.h>
#include <Wincrypt.h>
#include<iostream>
#pragma comment(lib, "Crypt32.lib")
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void MyHandleError(char *s);

static int callback(void *data, int argc, char **argv, char **azColName) {
	//std::cout << azColName[1] << std::endl;
	DATA_BLOB DataIn ;
	DATA_BLOB DataVerify;
	BYTE *pbDataInput = (BYTE *)azColName[1];
	DWORD cbDataInput = strlen((char *)pbDataInput) + 1;
	DataIn.pbData = pbDataInput;
	DataIn.cbData = cbDataInput;

	/////--------------------------------------------------------
	if (CryptUnprotectData(
		&DataIn,
		NULL,
		NULL,
		NULL,
		NULL,
		0,
		&DataVerify))
	{

		printf("The decrypted data is: %s\n", DataVerify.pbData);

	}

	else
	{
		MyHandleError("Decryption error!");
	}

	//-------------------------------------------------------------------

	return 0;
}

int main(int argc, char* argv[]) {
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
	char *sql;
	const char* data = "Callback function called";

	/* Open database */
	rc = sqlite3_open("test.db", &db);

	if (rc) {
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return(0);
	}
	else {
		fprintf(stderr, "Opened database successfully\n");
	}

	/* Create SQL statement */
	sql = "SELECT password_value FROM logins";

	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);

	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		fprintf(stdout, "Operation done successfully\n");
	}
	sqlite3_close(db);
}


void MyHandleError(char *s)
{
	fprintf(stderr, "An error occurred in running the program. \n");
	fprintf(stderr, "%s\n", s);
	fprintf(stderr, "Error number %x.\n", GetLastError());
	fprintf(stderr, "Program terminating. \n");
	exit(1);
} // End of MyHandleError
