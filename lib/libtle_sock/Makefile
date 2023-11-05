# Copyright (c) 2016 Intel Corporation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(TLDK_ROOT),)
$(error "Please define TLDK_ROOT environment variable")
endif

# Default target, can be overwritten by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(TLDK_ROOT)/dpdk_20.05_mk/rte.vars.mk

# library name
LIB = libtle_sock.a

ifeq ($(DEBUG),)
CFLAGS += -O3
else
CFLAGS += -O0 -ggdb
endif

 CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR)

EXPORT_MAP := tle_sock_version.map

LIBABIVER := 1

#source files
SRCS-y += tle_sock.c

SYMLINK-y-include += tle_sock.h

include $(TLDK_ROOT)/mk/tle.lib.mk
