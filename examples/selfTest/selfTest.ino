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

#define SUPPRESSCOLLORS
#include "fprint.h"  

void loop()
{
  uint32_t ret = 0; 
  /*
   * Authenticating OPTIGA™ Trust X chip
   */
  printGreen("Authenticating OPTIGA(TM) Trust X chip... ");
  ret = trustX.checkChip();
  if (ret) {
    printlnRed("Failed");
    while (true);
  }
  printlnGreen("OK");

  delay(2000);
}

void setup()
{
	uint32_t ret = 0;

  /*
   * Initialise serial output
   */
	Serial.begin(38400);
	Serial.println("Initializing ... ");

  /*
   * Initialise OPTIGA™ Trust X
   */
	printGreen("Begin Trust ... ");
	ret = trustX.begin();
	if (ret) {
	  printlnRed("Failed");
	  while (true);
	}
	printlnGreen("OK");

  /*
   * Speed up the chip (min is 6ma, maximum is 15ma)
   */
  printGreen("Setting Current Limit... ");
	ret = trustX.setCurrentLimit(15);
	if (ret) {
    printlnRed("Failed");
    while (true);
  }
	printlnGreen("OK");
}