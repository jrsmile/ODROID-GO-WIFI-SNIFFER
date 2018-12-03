/*
  ===========================================
       Copyright (c) 2017 Stefan Kremser - ArduinoPCAP Library
              github.com/spacehuhn
       Copyright (c) 2018 Jan Reiss - ODROID-GO Port
              github.com/JRSmile
  ===========================================
*/


/* include all necessary libraries */ 
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_internal.h"
#include "lwip/err.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include <Arduino.h>
#include <TimeLib.h>
#include "FS.h"
#include "SD.h"
#include "SPI.h"
#include <PCAP.h>
#include "Config.h"
#include "Display.h"

//===== SETTINGS =====//
#define CHANNEL 1
#define FILENAME "esp32"
#define SAVE_INTERVAL 30 //save new file every 30s
#define CHANNEL_HOPPING true //if true it will scan on all channels
#define MAX_CHANNEL 11 //(only necessary if channelHopping is true)
#define HOP_INTERVAL 214 //in ms (only necessary if channelHopping is true)
#define TFT_CS 5  // Chip select control pin LCD
#define TFT_DC 21  // Data Command control pin LCD
#define TEXT_HEIGHT 16 // Height of text to be printed and scrolled
#define BOT_FIXED_AREA 0 // Number of lines in bottom fixed area (lines counted from bottom of screen)
#define TOP_FIXED_AREA 16 // Number of lines in top fixed area (lines counted from top of screen)

//===== Run-Time variables =====//
// The initial y coordinate of the top of the scrolling area
uint16_t yStart = TOP_FIXED_AREA;
// yArea must be a integral multiple of TEXT_HEIGHT
uint16_t yArea = 320-TOP_FIXED_AREA-BOT_FIXED_AREA;
// The initial y coordinate of the top of the bottom text line
uint16_t yDraw = 320 - BOT_FIXED_AREA - TEXT_HEIGHT;
// Keep track of the drawing x coordinate
uint16_t xPos = 0;
// We have to blank the top line each time the display is scrolled, but this takes up to 13 milliseconds
// for a full width line, meanwhile the serial buffer may be filling... and overflowing
// We can speed up scrolling of short text lines by just blanking the character we drew
int blank[19]; // We keep all the strings pixel lengths to optimise the speed of the top line blanking

unsigned long lastTime = 0;
unsigned long lastChannelChange = 0;
int counter = 0;
int ch = CHANNEL;
bool fileOpen = false;

PCAP pcap = PCAP();
ILI9341 lcd = ILI9341();

//===== FUNCTIONS =====//

/* will be executed on every packet the ESP32 gets while beeing in promiscuous mode */
void sniffer(void *buf, wifi_promiscuous_pkt_type_t type){
  
  if(fileOpen){
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
  
    uint32_t timestamp = now(); //current timestamp 
    uint32_t microseconds = (unsigned int)(micros() - millis() * 1000); //micro seconds offset (0 - 999)
    pcap.newPacketSD(timestamp, microseconds, ctrl.sig_len, pkt->payload); //write packet to file
    
  }
  
}

esp_err_t event_handler(void *ctx, system_event_t *event){ return ESP_OK; }

// ##############################################################################################
// Setup the vertical scrolling start address
// ##############################################################################################
void scrollAddress(uint16_t VSP) {
  lcd.writecommand(ILI9341_VSCRSADD); // Vertical scrolling start address
  lcd.writedata(VSP>>8);
  lcd.writedata(VSP);
}

// ##############################################################################################
// Call this function to scroll the display one text line
// ##############################################################################################
int scroll_line() {
  int yTemp = yStart; // Store the old yStart, this is where we draw the next line
  // Use the record of line lengths to optimise the rectangle size we need to erase the top line
  lcd.fillRect(0,yStart,blank[(yStart-TOP_FIXED_AREA)/TEXT_HEIGHT],TEXT_HEIGHT, ILI9341_BLACK);

  // Change the top of the scroll area
  yStart+=TEXT_HEIGHT;
  // The value must wrap around as the screen memory is a circular buffer
  if (yStart >= 320 - BOT_FIXED_AREA) yStart = TOP_FIXED_AREA + (yStart - 320 + BOT_FIXED_AREA);
  // Now we can scroll the display
  scrollAddress(yStart);
  return  yTemp;
}

// ##############################################################################################
// Setup a portion of the screen for vertical scrolling
// ##############################################################################################
// We are using a hardware feature of the display, so we can only scroll in portrait orientation
void setupScrollArea(uint16_t TFA, uint16_t BFA) {
  lcd.writecommand(ILI9341_VSCRDEF); // Vertical scroll definition
  lcd.writedata(TFA >> 8);
  lcd.writedata(TFA);
  lcd.writedata((320-TFA-BFA)>>8);
  lcd.writedata(320-TFA-BFA);
  lcd.writedata(BFA >> 8);
  lcd.writedata(BFA);
}


/* opens a new file */
void openFile(){

  //searches for the next non-existent file name
  int c = 0;
  String filename = "/" + (String)FILENAME + ".pcap";
  while(SD.open(filename)){
    filename = "/" + (String)FILENAME + "_" + (String)c + ".pcap";
    c++;
  }
  
  //set filename and open the file
  pcap.filename = filename;
  fileOpen = pcap.openFile(SD);

  Serial.println("open: "+filename);
  lcd.println("o:"+filename);
  scroll_line();

  //reset counter (counter for saving every X seconds)
  counter = 0;
}



//===== SETUP =====//
void setup() {
  
  Serial.begin(115200);
  delay(2000);
  Serial.println();
  lcd.begin();
  lcd.setBrightness(10);
  lcd.fillScreen(ILI9341_BLACK);
  setupScrollArea(TOP_FIXED_AREA, BOT_FIXED_AREA);
  // lcd.setRotation(3); Rotation of the screen is not possible
  lcd.setTextSize(2);
  scroll_line();
  lcd.println("ODROID Wifi Sniffer"); 

    /* initialize SD card */
  if(!SD.begin()){
    Serial.println("Card Mount Failed");
    scroll_line();
    lcd.println("Card Mount Failed");
    return;
  }
  
  uint8_t cardType = SD.cardType();
  
  if(cardType == CARD_NONE){
      Serial.println("No SD card attached");
      scroll_line();
      lcd.println("No SD card attached");
      return;
  }

  Serial.print("Card Type: ");
  scroll_line();
  lcd.print("Card Type: ");
  if(cardType == CARD_MMC){
      Serial.println("MMC");
      lcd.println("MMC");
  } else if(cardType == CARD_SD){
      Serial.println("SDSC");
      lcd.println("SDSC");
  } else if(cardType == CARD_SDHC){
      Serial.println("SDHC");
      lcd.println("SDHC");
  } else {
      Serial.println("UNKNOWN");
      lcd.println("UNKNOWN");
  }


  int64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("Card Size: %lluMB\n", cardSize);
  scroll_line();
  lcd.printf("Card Size: %lluMB\n", cardSize);
    
  openFile();

  /* setup wifi */
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_AP) );  
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniffer);
  wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
  esp_wifi_set_channel(ch,secondCh);

  Serial.println("Sniffer started!");
  scroll_line();
  lcd.println("Sniffer started!");
}

void loop() {
  unsigned long currentTime = millis();
  
  /* Channel Hopping */
  if(CHANNEL_HOPPING){
    if(currentTime - lastChannelChange >= HOP_INTERVAL){
      lastChannelChange = currentTime;
      ch++; //increase channel
      if(ch > MAX_CHANNEL) ch = 1;
      wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
      esp_wifi_set_channel(ch,secondCh);
    }
  }
  
	/* for every second */
  if(fileOpen && currentTime - lastTime > 1000){
    pcap.flushFile(); //save file
    lastTime = currentTime; //update time
    counter++; //add 1 to counter
  }
  /* when counter > 30s interval */
  if(fileOpen && counter > SAVE_INTERVAL){
    pcap.closeFile(); //save & close the file
    fileOpen = false; //update flag
    Serial.println("==================");
    Serial.println(pcap.filename + " saved!");
    Serial.println("==================");
    scroll_line();
    lcd.println("s:" + pcap.filename);
    openFile(); //open new file
  }

}