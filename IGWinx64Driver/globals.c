#include "globals.h"

// atribuindo valores iniciais às variáveis globais para evitar erros de linker
PFLT_FILTER g_FilterHandle = NULL;
PDEVICE_OBJECT g_DeviceObject = NULL;
PFLT_PORT g_ServerPort = NULL;
DRIVER_CONTEXT g_driverContext = { NULL };