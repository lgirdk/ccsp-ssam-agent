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

#include "ansc_platform.h"
#include "ansc_load_library.h"
#include "cosa_plugin_api.h"
#include "plugin_main.h"
#include "cosa_apis_ssamagentplugin.h"

#define THIS_PLUGIN_VERSION 1

int COSA_Init(ULONG uMaxVersionSupported, void *hCosaPlugInfo)
{
    PCOSA_PLUGIN_INFO pPlugInfo = (PCOSA_PLUGIN_INFO) hCosaPlugInfo;

    if (uMaxVersionSupported < THIS_PLUGIN_VERSION) {
        return -1;
    }

    pPlugInfo->uPluginVersion = THIS_PLUGIN_VERSION;

    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_LGI_COM_DigitalSecurity_GetParamUlongValue", X_LGI_COM_DigitalSecurity_GetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_LGI_COM_DigitalSecurity_SetParamUlongValue", X_LGI_COM_DigitalSecurity_SetParamUlongValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_LGI_COM_DigitalSecurity_GetParamStringValue", X_LGI_COM_DigitalSecurity_GetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_LGI_COM_DigitalSecurity_SetParamStringValue", X_LGI_COM_DigitalSecurity_SetParamStringValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_LGI_COM_DigitalSecurity_GetParamBoolValue", X_LGI_COM_DigitalSecurity_GetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_LGI_COM_DigitalSecurity_SetParamBoolValue", X_LGI_COM_DigitalSecurity_SetParamBoolValue);
    pPlugInfo->RegisterFunction(pPlugInfo->hContext, "X_LGI_COM_DigitalSecurity_Commit", X_LGI_COM_DigitalSecurity_Commit);

    return 0;
}

BOOL COSA_IsObjectSupported(char *pObjName)
{
    return TRUE;
}

void COSA_Unload(void)
{
}
