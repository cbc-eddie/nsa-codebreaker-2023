# Task 2 - Extract the Firmware
![Static Badge](https://img.shields.io/badge/Categories-Hardware%20Analysis%2C%20Datasheets-blue)
![Static Badge](https://img.shields.io/badge/Points-100-light_green)

> Thanks to your efforts the USCG discovered the unknown object by trilaterating the geo and timestamp entries of their record with the correlating entries you provided from the NSA databases. Upon discovery, the device appears to be a device with some kind of collection array used for transmitting and receiving. Further visual inspection shows the brains of this device to be reminiscent of a popular hobbyist computer. Common data and visual ports non-responsive; the only exception is a boot prompt output when connecting over HDMI. Most interestingly there is a 40pin GPIO header with an additional 20pin header. Many of these physical pins show low-voltage activity which indicate data may be enabled. There may be a way to still interact with the device firmware...
> 
> Find the correct processor datasheet, and then use it and the resources provided to enter which physical pins enable data to and from this device
> 
> Hints:
> - Note: For the pinout.svg, turn off your application's dark mode if you're unable to see the physical pin labels (eg: 'P1', 'P60')
> - The pinout.svg has two voltage types. The gold/tan is 3.3v, the red is 5v.
> - The only additional resource you will need is the datasheet, or at least the relevant information from it
> 
> 
> Downloads:
> - Rendering of debug ports on embedded computer (pinout.svg)
> - image of device CPU (cpu.jpg)
> - copy of display output when attempting to read from HDMI (boot_prompt.log)
> 
> ---
> Prompts:
> - Provide the correct physical pin number to power the GPIO header
> - Provide a correct physical pin number to ground the board
> - Provide the correct physical pin number for a UART transmit function
> - Provide the correct physical pin number for a UART receive function

## Solution
We're tasked with gathering additional information on the hardware device so that we can eventually communicate with it over UART and extract its firmware. Searching the model number off the CPU in the provided image leads us to some [Raspberry Pi documentation](https://www.raspberrypi.com/documentation/computers/processors.html) and tells us it might be the type of device we're dealing with.

Searching for GPIO voltage information leads us to some [resources that point to 3.3v over 5v] (https://forums.raspberrypi.com/viewtopic.php?t=321910). The pinout legend also tells us that gray circles indicate grounds. We can use this information to select `P10` as the correct physical pin to the power the GPIO header and the nearby `P9` as our ground.

We now need to find the correct UART transmit and receive pins. Taking a closer look at our boot log output, we'll see a line specifying the `Alternative Function Assignment`. In this case, it tells us it's using `ALT5`.

```
***********************************************************
*                                                                  *
*                  Operation PITS Boot-up Banner                   *
*                                                                  *
********************************************************************
device name:
Model: XYZ-1234
Firmware Version: 1.0.0
Boot Time: 1970-01-01 00:00:00
Initializing collector...
Loading configuration...
Starting services...
Booting up...
Collector is online.
Alternative Function Assignment  :  ALT5
```

Searching for BCM2837 datasheet information will lead us to [this document on BC2837 ARM peripherals](https://cs140e.sergio.bz/docs/BCM2837-ARM-Peripherals.pdf). There's a chart on page 102 that provides additional information on pin locations for alternative function assignments. We'll see `TXD1` is listed next to `GPIO14` and `GPIO32` while `RXD1` is listed next to `GPIO15` and `GPIO33`. Our board doesn't have `GPIO14` or `GPIO15` listed on the pinout image, but `GPIO32` and `GPIO32` correspond to pins `P37` and `P38`, respectively. We now have all four pieces of information we need and submit the below pins as the solution.

```
Power: P10
Ground: P9
UART Tx: P37
UART Rx: P38
```
