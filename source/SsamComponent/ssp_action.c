/*****************************************************************************
 * Copyright 2021 Liberty Global B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ****************************************************************************/

#include "ssp_global.h"
#include "plugin_main.h"
#include "dslh_dmagnt_interface.h"
#include "ccsp_trace.h"
#include "dm_pack_create_func.h"
#include "safec_lib_common.h"

PDSLH_CPE_CONTROLLER_OBJECT pDslhCpeController = NULL;
PCOMPONENT_COMMON_SSAMAGENT g_pComponent_COMMON_ssamagent = NULL;
PCCSP_CCD_INTERFACE pSsdCcdIf = (PCCSP_CCD_INTERFACE) NULL;
PDSLH_LCB_INTERFACE pDslhLcbIf = (PDSLH_LCB_INTERFACE) NULL;
extern char g_Subsystem[32];

#define CCSP_DATAMODEL_XML_FILE "SsamAgent.xml"

extern ANSC_HANDLE bus_handle;
extern ULONG g_ulAllocatedSizePeak;

ANSC_STATUS ssp_create(void)
{
    g_pComponent_COMMON_ssamagent = (PCOMPONENT_COMMON_SSAMAGENT) AnscAllocateMemory(sizeof(COMPONENT_COMMON_SSAMAGENT));
    if (!g_pComponent_COMMON_ssamagent) {
        return ANSC_STATUS_RESOURCES;
    }

    ComponentCommonDmInit(g_pComponent_COMMON_ssamagent);
    g_pComponent_COMMON_ssamagent->Name = AnscCloneString(CCSP_COMPONENT_NAME_SSAMAGENT);
    g_pComponent_COMMON_ssamagent->Version = 1;
    g_pComponent_COMMON_ssamagent->Author = AnscCloneString("Your name");

    if (!pSsdCcdIf) {
        pSsdCcdIf = (PCCSP_CCD_INTERFACE) AnscAllocateMemory(sizeof(CCSP_CCD_INTERFACE));
        if (!pSsdCcdIf) {
            return ANSC_STATUS_RESOURCES;
        }

        strcpy(pSsdCcdIf->Name, CCSP_CCD_INTERFACE_NAME);
        pSsdCcdIf->InterfaceId = CCSP_CCD_INTERFACE_ID;
        pSsdCcdIf->hOwnerContext = NULL;
        pSsdCcdIf->Size = sizeof(CCSP_CCD_INTERFACE);

        pSsdCcdIf->GetComponentName = ssp_CcdIfGetComponentName;
        pSsdCcdIf->GetComponentVersion = ssp_CcdIfGetComponentVersion;
        pSsdCcdIf->GetComponentAuthor = ssp_CcdIfGetComponentAuthor;
        pSsdCcdIf->GetComponentHealth = ssp_CcdIfGetComponentHealth;
        pSsdCcdIf->GetComponentState = ssp_CcdIfGetComponentState;
        pSsdCcdIf->GetLoggingEnabled = ssp_CcdIfGetLoggingEnabled;
        pSsdCcdIf->SetLoggingEnabled = ssp_CcdIfSetLoggingEnabled;
        pSsdCcdIf->GetLoggingLevel = ssp_CcdIfGetLoggingLevel;
        pSsdCcdIf->SetLoggingLevel = ssp_CcdIfSetLoggingLevel;
        pSsdCcdIf->GetMemMaxUsage = ssp_CcdIfGetMemMaxUsage;
        pSsdCcdIf->GetMemMinUsage = ssp_CcdIfGetMemMinUsage;
        pSsdCcdIf->GetMemConsumed = ssp_CcdIfGetMemConsumed;
        pSsdCcdIf->ApplyChanges = ssp_CcdIfApplyChanges;
    }

    if (!pDslhLcbIf) {
        pDslhLcbIf = (PDSLH_LCB_INTERFACE) AnscAllocateMemory(sizeof(DSLH_LCB_INTERFACE));
        if (!pDslhLcbIf) {
            return ANSC_STATUS_RESOURCES;
        }

        strcpy(pDslhLcbIf->Name, CCSP_LIBCBK_INTERFACE_NAME);
        pDslhLcbIf->InterfaceId = CCSP_LIBCBK_INTERFACE_ID;
        pDslhLcbIf->hOwnerContext = NULL;
        pDslhLcbIf->Size = sizeof(DSLH_LCB_INTERFACE);

        pDslhLcbIf->InitLibrary = COSA_Init;
    }

    pDslhCpeController = DslhCreateCpeController(NULL, NULL, NULL);
    if (!pDslhCpeController) {
        CcspTraceWarning(("CANNOT Create pDslhCpeController... Exit!\n"));
        return ANSC_STATUS_RESOURCES;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS ssp_engage(void)
{
    char CrName[256];
    PCCC_MBI_INTERFACE pSsdMbiIf;
    ANSC_STATUS returnStatus;

    pSsdMbiIf = (PCCC_MBI_INTERFACE) MsgHelper_CreateCcdMbiIf((void *)bus_handle, g_Subsystem);

    g_pComponent_COMMON_ssamagent->Health = CCSP_COMMON_COMPONENT_HEALTH_Yellow;

    pDslhCpeController->AddInterface((ANSC_HANDLE) pDslhCpeController, (ANSC_HANDLE) pDslhLcbIf);
    pDslhCpeController->AddInterface((ANSC_HANDLE) pDslhCpeController, (ANSC_HANDLE) pSsdMbiIf);
    pDslhCpeController->AddInterface((ANSC_HANDLE) pDslhCpeController, (ANSC_HANDLE) pSsdCcdIf);
    pDslhCpeController->SetDbusHandle((ANSC_HANDLE) pDslhCpeController, (ANSC_HANDLE) bus_handle);
    pDslhCpeController->Engage((ANSC_HANDLE) pDslhCpeController);

    sprintf(CrName, "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);

    returnStatus = pDslhCpeController->RegisterCcspDataModel2((ANSC_HANDLE) pDslhCpeController, /* CCSP_DBUS_INTERFACE_CR, */
                                                              CrName,                           /* CCSP CR ID */
                                                              DMPackCreateDataModelXML,         /* Data Model XML file. Can be empty if only base data model supported. */
                                                              CCSP_COMPONENT_NAME_SSAMAGENT,    /* Component Name    */
                                                              CCSP_COMPONENT_VERSION_SSAMAGENT, /* Component Version */
                                                              CCSP_COMPONENT_PATH_SSAMAGENT,    /* Component Path    */
                                                              g_Subsystem);                     /* Component Prefix  */

    if (returnStatus == ANSC_STATUS_SUCCESS) {
        g_pComponent_COMMON_ssamagent->Health = CCSP_COMMON_COMPONENT_HEALTH_Green;
    }

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS ssp_cancel(void)
{
    char CrName[256];
    char CpName[256];
    int nRet;

    if (g_pComponent_COMMON_ssamagent == NULL) {
        return ANSC_STATUS_SUCCESS;
    }

    sprintf(CrName, "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
    sprintf(CpName, "%s%s", g_Subsystem, CCSP_COMPONENT_NAME_SSAMAGENT);

    nRet = CcspBaseIf_unregisterComponent(bus_handle, CrName, CpName);
    AnscTrace("unregisterComponent returns %d\n", nRet);

    pDslhCpeController->Cancel((ANSC_HANDLE) pDslhCpeController);
    AnscFreeMemory(pDslhCpeController);
    pDslhCpeController = NULL;

    if (pSsdCcdIf) {
        AnscFreeMemory(pSsdCcdIf);
        pSsdCcdIf = NULL;
    }

    if (g_pComponent_COMMON_ssamagent) {
        AnscFreeMemory(g_pComponent_COMMON_ssamagent);
        g_pComponent_COMMON_ssamagent = NULL;
    }

    return ANSC_STATUS_SUCCESS;
}

char *ssp_CcdIfGetComponentName(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->Name;
}

ULONG ssp_CcdIfGetComponentVersion(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->Version;
}

char *ssp_CcdIfGetComponentAuthor(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->Author;
}

ULONG ssp_CcdIfGetComponentHealth(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->Health;
}

ULONG ssp_CcdIfGetComponentState(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->State;
}

BOOL ssp_CcdIfGetLoggingEnabled(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->LogEnable;
}

ANSC_STATUS ssp_CcdIfSetLoggingEnabled(ANSC_HANDLE hThisObject, BOOL bEnabled)
{
    if (g_pComponent_COMMON_ssamagent->LogEnable == bEnabled) {
        return ANSC_STATUS_SUCCESS;
    }

    g_pComponent_COMMON_ssamagent->LogEnable = bEnabled;

    if (bEnabled) {
        g_iTraceLevel = (INT) g_pComponent_COMMON_ssamagent->LogLevel;
    }
    else {
        g_iTraceLevel = CCSP_TRACE_INVALID_LEVEL;
    }

    return ANSC_STATUS_SUCCESS;
}

ULONG ssp_CcdIfGetLoggingLevel(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->LogLevel;
}

ANSC_STATUS ssp_CcdIfSetLoggingLevel(ANSC_HANDLE hThisObject, ULONG LogLevel)
{
    if (g_pComponent_COMMON_ssamagent->LogLevel == LogLevel) {
        return ANSC_STATUS_SUCCESS;
    }

    g_pComponent_COMMON_ssamagent->LogLevel = LogLevel;

    if (g_pComponent_COMMON_ssamagent->LogEnable) {
        g_iTraceLevel = (INT) g_pComponent_COMMON_ssamagent->LogLevel;
    }

    return ANSC_STATUS_SUCCESS;
}

ULONG ssp_CcdIfGetMemMaxUsage(ANSC_HANDLE hThisObject)
{
    return g_ulAllocatedSizePeak;
}

ULONG ssp_CcdIfGetMemMinUsage(ANSC_HANDLE hThisObject)
{
    return g_pComponent_COMMON_ssamagent->MemMinUsage;
}

ULONG ssp_CcdIfGetMemConsumed(ANSC_HANDLE hThisObject)
{
    LONG size;

    size = AnscGetComponentMemorySize(CCSP_COMPONENT_NAME_SSAMAGENT);
    if (size == -1) {
        size = 0;
    }

    return size;
}

ANSC_STATUS ssp_CcdIfApplyChanges(ANSC_HANDLE hThisObject)
{
    return ANSC_STATUS_SUCCESS;
}
