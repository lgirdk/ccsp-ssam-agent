##########################################################################
# Copyright 2021 Liberty Global B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

bin_PROGRAMS = ssam_agent

ssam_agent_CPPFLAGS = -I$(top_srcdir)/source/SsamComponent -I=${includedir}/ccsp
ssam_agent_CFLAGS = $(DBUS_CFLAGS)
ssam_agent_SOURCES = cosa_apis_ssamagentplugin.c plugin_main.c ssp_action.c ssp_messagebus_interface.c ssp_main.c dm_pack_datamodel.c
ssam_agent_LDFLAGS = -lccsp_common -lrdkloggers -lsysevent -lsyscfg -lulog $(DBUS_LIBS) -lpthread
