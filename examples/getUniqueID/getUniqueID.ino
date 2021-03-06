/**
 * MIT License
 *
 * Copyright (c) 2018 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 *
 * Demonstrates use of the 
 * Infineon Technologies AG OPTIGA™ Trust X Arduino library
 */

#include "OPTIGATrustX.h"

#define UID_LENGTH        27

#define SUPPRESSCOLLORS
#include "fprint.h"

void setup() 
{
  uint32_t ret = 0;
  
  /*
   * Initialise a serial port for debug output
   */
  Serial.begin(38400);
  delay(1000);
  Serial.println("Initializing ... ");

  /*
   * Initialise an OPTIGA™ Trust X Board
   */
  printGreen("Begin to trust ... ");
  ret = trustX.begin();
  if (ret) {
    printlnRed("Failed");
    while (true);
  }
  printlnGreen("OK");

  /*
   * Speedup the board (from 6 mA to 15 mA)
   */
  printGreen("Limiting Current consumption (15mA - means no limitation) ... ");
  ret = trustX.setCurrentLimit(15);
  if (ret) {
    printlnRed("Failed");
    while (true);
  }
  printlnGreen("OK");

}

void loop()
{
  uint32_t ret = 0;
  uint8_t  cntr = 10;
  uint8_t  uid[UID_LENGTH];
  uint16_t uidLength = UID_LENGTH;
  /*
   * Getting co-processor Unique ID of 27 bytes
   */
  printlnGreen("\r\nGetting co-processor Unique ID... ");
  ret = trustX.getUniqueID(uid, uidLength);
  if (ret) {
    printlnRed("Failed");
    while (true);
  }

  printlnGreen("OK"); 
  printMagenta("Unique ID Length: ");
  Serial.println(uidLength);
  printlnMagenta("Unique ID:");
  HEXDUMP(uid, uidLength);

  /*
   * Count down 10 seconds and restart the application
   */
  while(cntr) {
    Serial.print(cntr);
    Serial.println(" seconds untill restart.");
    delay(1000);
    cntr--;
  }
}
