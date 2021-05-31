#include <linux/device.h>
#include <linux/init.h>

extern int devices_init(void);
extern int buses_init(void);
extern int classes_init(void);
extern int firmware_init(void);
extern int platform_bus_init(void);
extern int system_bus_init(void);
extern int cpu_dev_init(void);
extern int attribute_container_init(void);

void __init driver_init(void)
{
    devices_init();
    buses_init();
    classes_init();
    firmware_init();

    platform_bus_init();
    system_bus_init();
    cpu_dev_init();
    attribute_container_init();
}