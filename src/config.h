#pragma once

/* Build switches can be overridden with -DNAME=value in compiler flags. */
#ifndef DOWNGRADE_ALLOWED
#   define DOWNGRADE_ALLOWED        1   /* Permit valid firmware with an older timestamp. */
#endif

#ifndef USE_LED
#   define USE_LED                  1   /* Enable onboard LED status indication. */
#endif

#ifndef APPLICATION_CRC_CHECK
#   define APPLICATION_CRC_CHECK    1   /* Check application CRC on every boot. */
#endif

#ifndef RDP_LEVEL
#   define RDP_LEVEL                0   /* 0: debug access; 1: readout protection. */
#endif

#ifndef DUAL_BANK_FLASH
#   define DUAL_BANK_FLASH          0   /* Enable bank-aware FMC and NVStorage paths. */
#endif

#if ((DOWNGRADE_ALLOWED != 0) && (DOWNGRADE_ALLOWED != 1)) || \
    ((USE_LED != 0) && (USE_LED != 1)) || \
    ((APPLICATION_CRC_CHECK != 0) && (APPLICATION_CRC_CHECK != 1)) || \
    ((RDP_LEVEL != 0) && (RDP_LEVEL != 1))
#   error DOWNGRADE_ALLOWED, USE_LED, APPLICATION_CRC_CHECK, and RDP_LEVEL must be 0 or 1
#endif

#if (DUAL_BANK_FLASH != 0) && (DUAL_BANK_FLASH != 1)
#   error DUAL_BANK_FLASH must be 0 or 1
#endif

