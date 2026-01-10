#include <Arduino.h>

#ifndef GD32F30x
#   error Unsupported MCU!!!
#endif

#define LED     PB2
#define DELAY   500

#if defined(FLASH_OFFSET) && FLASH_OFFSET != 0
__attribute__((constructor(102))) void vtor_init()
{
    // Calculate the start address based on the flash base and defined offset
    constexpr uint32_t THIS_APP_START_ADDRESS   {FLASH_BASE + (uint32_t)(FLASH_OFFSET)};

    SCB->VTOR = THIS_APP_START_ADDRESS;
    __DSB();
}
#endif

void setup()
{
    pinMode(LED, OUTPUT);
}

void loop()
{
    digitalWrite(LED, LOW);
    delay(DELAY);
    digitalWrite(LED, HIGH);
    delay(DELAY);
}
