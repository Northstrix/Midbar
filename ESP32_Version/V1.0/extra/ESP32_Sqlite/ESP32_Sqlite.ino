/*
Project Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/GyverLibs/GyverBus
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
*/
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <SPI.h>
#include <FS.h>
#include "SPIFFS.h"

/* You only need to format SPIFFS the first time you run a
   test or else use the SPIFFS plugin to create a partition
   https://github.com/me-no-dev/arduino-esp32fs-plugin */
   
#define FORMAT_SPIFFS_IF_FAILED true
const char* data = "Callback function called";
static int callback(void *data, int argc, char **argv, char **azColName) {
   int i;
   Serial.printf("%s: ", (const char*)data);
   for (i = 0; i<argc; i++){
       Serial.printf("\n%s = %s", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   Serial.printf("\n\n");
   return 0;
}

int db_open(const char *filename, sqlite3 **db) {
   int rc = sqlite3_open(filename, db);
   if (rc) {
       Serial.printf("Can't open database: %s\n", sqlite3_errmsg(*db));
       return rc;
   } else {
       Serial.printf("Opened database successfully\n");
   }
   return rc;
}

char *zErrMsg = 0;
int db_exec(sqlite3 *db, const char *sql) {
   int rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
   if (rc != SQLITE_OK) {
       Serial.printf("SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
   } else {
       Serial.printf("Operation done successfully\n");
   }
   return rc;
}

void create_login_table(){
   sqlite3 *db1;
   int rc;
   if (db_open("/spiffs/midbar.db", &db1))
       return;

   rc = db_exec(db1, "CREATE TABLE if not exists Logins (ID CHARACTER(36), Title TEXT, Username TEXT, Password TEXT, Website Text);");
   if (rc != SQLITE_OK) {
       sqlite3_close(db1);
       return;
   }
   sqlite3_close(db1);
}

void create_credit_card_table(){
   sqlite3 *db1;
   int rc;
   if (db_open("/spiffs/midbar.db", &db1))
       return;

   rc = db_exec(db1, "CREATE TABLE if not exists Credit_cards (ID CHARACTER(40), Title TEXT, Cardholder TEXT, Card_Number TEXT, Expiration_date Text, CVN Text, PIN Text, ZIP_code Text);");
   if (rc != SQLITE_OK) {
       sqlite3_close(db1);
       return;
   }
   sqlite3_close(db1);
}

void create_notes_table(){
   sqlite3 *db1;
   int rc;
   if (db_open("/spiffs/midbar.db", &db1))
       return;

   rc = db_exec(db1, "CREATE TABLE if not exists Notes (ID CHARACTER(34), Title TEXT, Content TEXT);");
   if (rc != SQLITE_OK) {
       sqlite3_close(db1);
       return;
   }
   sqlite3_close(db1);
}

void exeq_sql_statement(char query[]){
   sqlite3 *db1;
   int rc;
   if (db_open("/spiffs/midbar.db", &db1))
       return;

   rc = db_exec(db1, query);
   if (rc != SQLITE_OK) {
       sqlite3_close(db1);
       return;
   }

   sqlite3_close(db1);
}

void setup() {
   Serial.begin(115200);
   if (!SPIFFS.begin(FORMAT_SPIFFS_IF_FAILED)) {
       Serial.println("Failed to mount file system");
       return;
   }
   // list SPIFFS contents
   File root = SPIFFS.open("/");
   if (!root) {
       Serial.println("- failed to open directory");
       return;
   }
   if (!root.isDirectory()) {
       Serial.println(" - not a directory");
       return;
   }
   File file = root.openNextFile();
   while (file) {
       if (file.isDirectory()) {
           Serial.print("  DIR : ");
           Serial.println(file.name());
       } else {
           Serial.print("  FILE: ");
           Serial.print(file.name());
           Serial.print("\tSIZE: ");
           Serial.println(file.size());
       }
       file = root.openNextFile();
   }
   sqlite3_initialize();
   create_login_table();
   create_credit_card_table();
   create_notes_table();
   disp_all_logins();
}

void loop() {
      Serial.println("Enter the sql statement to execute:");
      while (!Serial.available()) {}
      String squery = Serial.readString();
      int squery_len = squery.length() + 1;
      char squery_array[squery_len];
      squery.toCharArray(squery_array, squery_len);
      exeq_sql_statement(squery_array);
}
