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

#ifndef _SSP_INTERNAL_H_
#define _SSP_INTERNAL_H_

#define CCSP_COMMON_COMPONENT_HEALTH_Red 1
#define CCSP_COMMON_COMPONENT_HEALTH_Yellow 2
#define CCSP_COMMON_COMPONENT_HEALTH_Green 3

#define CCSP_COMMON_COMPONENT_STATE_Initializing 1
#define CCSP_COMMON_COMPONENT_STATE_Running 2
#define CCSP_COMMON_COMPONENT_STATE_Blocked 3
#define CCSP_COMMON_COMPONENT_STATE_Paused 3

#define CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_High 1
#define CCSP_COMMON_COMPONENT_FREERESOURCES_PRIORITY_Low 2

#define CCSP_COMPONENT_ID_SSAMAGENT "com.cisco.spvtg.ccsp.ssamagent"
#define CCSP_COMPONENT_NAME_SSAMAGENT "com.cisco.spvtg.ccsp.ssamagent"
#define CCSP_COMPONENT_VERSION_SSAMAGENT 1
#define CCSP_COMPONENT_PATH_SSAMAGENT "/com/cisco/spvtg/ccsp/ssamagent"

#define MESSAGE_BUS_CONFIG_FILE "msg_daemon.cfg"

typedef struct _COMPONENT_COMMON_SSAMAGENT {
    char *Name;
    ULONG Version;
    char *Author;
    ULONG Health;
    ULONG State;
    BOOL LogEnable;
    ULONG LogLevel;
    ULONG MemMaxUsage;
    ULONG MemMinUsage;
    ULONG MemConsumed;
}
COMPONENT_COMMON_SSAMAGENT, *PCOMPONENT_COMMON_SSAMAGENT;

#define ComponentCommonDmInit(component_com_ssamagent)                         \
{                                                                              \
    AnscZeroMemory(component_com_ssamagent,                                    \
                   sizeof(COMPONENT_COMMON_SSAMAGENT));                        \
    component_com_ssamagent->Name = NULL;                                      \
    component_com_ssamagent->Version = 1;                                      \
    component_com_ssamagent->Author = NULL;                                    \
    component_com_ssamagent->Health = CCSP_COMMON_COMPONENT_HEALTH_Red;        \
    component_com_ssamagent->State = CCSP_COMMON_COMPONENT_STATE_Running;      \
    if (g_iTraceLevel >= CCSP_TRACE_LEVEL_EMERGENCY)                           \
        component_com_ssamagent->LogLevel = (ULONG)g_iTraceLevel;              \
    component_com_ssamagent->LogEnable = TRUE;                                 \
    component_com_ssamagent->MemMaxUsage = 0;                                  \
    component_com_ssamagent->MemMinUsage = 0;                                  \
    component_com_ssamagent->MemConsumed = 0;                                  \
}

#define ComponentCommonDmClean(component_com_ssamagent)                        \
{                                                                              \
    if (component_com_ssamagent->Name) {                                       \
        AnscFreeMemory(component_com_ssamagent->Name);                         \
        component_com_ssamagent->Name = NULL;                                  \
    }                                                                          \
    if (component_com_ssamagent->Author) {                                     \
        AnscFreeMemory(component_com_ssamagent->Author);                       \
        component_com_ssamagent->Author = NULL;                                \
    }                                                                          \
}

#define ComponentCommonDmFree(component_com_ssamagent)                         \
{                                                                              \
    ComponentCommonDmClean(component_com_ssamagent);                           \
    AnscFreeMemory(component_com_ssamagent);                                   \
    component_com_ssamagent = NULL;                                            \
}

int cmd_dispatch(int command);
ANSC_STATUS ssp_create(void);
ANSC_STATUS ssp_engage(void);
ANSC_STATUS ssp_cancel(void);
char *ssp_CcdIfGetComponentName(ANSC_HANDLE hThisObject);
ULONG ssp_CcdIfGetComponentVersion(ANSC_HANDLE hThisObject);
char *ssp_CcdIfGetComponentAuthor(ANSC_HANDLE hThisObject);
ULONG ssp_CcdIfGetComponentHealth(ANSC_HANDLE hThisObject);
ULONG ssp_CcdIfGetComponentState(ANSC_HANDLE hThisObject);
BOOL ssp_CcdIfGetLoggingEnabled(ANSC_HANDLE hThisObject);
ANSC_STATUS ssp_CcdIfSetLoggingEnabled(ANSC_HANDLE hThisObject, BOOL bEnabled);
ULONG ssp_CcdIfGetLoggingLevel(ANSC_HANDLE hThisObject);
ANSC_STATUS ssp_CcdIfSetLoggingLevel(ANSC_HANDLE hThisObject, ULONG LogLevel);
ULONG ssp_CcdIfGetMemMaxUsage(ANSC_HANDLE hThisObject);
ULONG ssp_CcdIfGetMemMinUsage(ANSC_HANDLE hThisObject);
ULONG ssp_CcdIfGetMemConsumed(ANSC_HANDLE hThisObject);
ANSC_STATUS ssp_CcdIfApplyChanges(ANSC_HANDLE hThisObject);

#endif
