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

AC_PREREQ([2.69])
AC_INIT([ccsp-ssam-agent], [1.0])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([source/SsamComponent/ssp_main.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

AC_CHECK_HEADERS([fcntl.h])

AC_TYPE_SIZE_T

AC_FUNC_FORK
AC_CHECK_FUNCS([dup2 memset mkdir strerror])

PKG_CHECK_MODULES([DBUS],[dbus-1 >= 1.6.18])

AC_CONFIG_FILES([Makefile
                 source/Makefile
                 source/SsamComponent/Makefile])
AC_OUTPUT
