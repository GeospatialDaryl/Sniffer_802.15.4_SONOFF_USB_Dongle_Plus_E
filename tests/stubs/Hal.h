/* Host-test stub for the firmware's Hal.h: only what console.c needs. */
#ifndef HAL_STUB_H
#define HAL_STUB_H
#include <stdint.h>
void HAL_SetRadioChannel( uint8_t channel );
void BSP_RebootInBootloader( void );
#endif
