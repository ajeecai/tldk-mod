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

TLDK_ROOT := $(CURDIR)
export TLDK_ROOT

LOCAL_RTE_SDK=$(TLDK_ROOT)/dpdk/_build/dpdk

ifeq ($(RTE_SDK),)
	export RTE_SDK=$(TLDK_ROOT)
endif



export RTE_TOOLCHAIN ?= gcc
export RTE_EXEC_ENV ?= linuxapp
export RTE_MACHINE ?= native
export RTE_ARCH ?= x86_64

RTE_TARGET ?= x86_64-native-linuxapp-gcc

DIRS-y += lib
DIRS-y += examples
DIRS-y += test

ifneq ($(MODULE),)
	DIRS-y = $(MODULE)
endif

MAKEFLAGS += --no-print-directory

# output directory
O ?= $(TLDK_ROOT)/${RTE_TARGET}
BASE_OUTPUT ?= $(abspath $(O))

ifeq ($(RTE_OUTPUT),)
	export RTE_OUTPUT=$(abspath $(O))
endif

ifeq ($(DPDK_ROOT),)
$(error "Please define DPDK_ROOT environment variable")
endif

.PHONY: all
all: $(DIRS-y)

.PHONY: clean
clean: $(DIRS-y)
	$(Q)rm -f $(TLDK_ROOT)/$(RTE_TARGET)/.config && \
		rm -f $(TLDK_ROOT)/$(RTE_TARGET)/include/rte_config.h \
		rm -rf $(TLDK_ROOT)/$(RTE_ARCH)-$(RTE_MACHINE)-$(RTE_EXEC_ENV)-$(RTE_TOOLCHAIN)

.PHONY: $(DIRS-y)
$(DIRS-y): $(TLDK_ROOT)/$(RTE_TARGET)/.config \
			$(TLDK_ROOT)/$(RTE_TARGET)/include/rte_config.h
	@echo "== $@"
	$(Q)$(MAKE) -C $(@) \
		M=$(CURDIR)/$(@)/Makefile \
		O=$(BASE_OUTPUT) \
		BASE_OUTPUT=$(BASE_OUTPUT) \
		CUR_SUBDIR=$(CUR_SUBDIR)/$(@) \
		S=$(CURDIR)/$(@) \
		RTE_TARGET=$(RTE_TARGET) \
		RTE_TOOLCHAIN=$(RTE_TOOLCHAIN) \
		RTE_EXEC_ENV=$(RTE_EXEC_ENV) \
		RTE_MACHINE=$(RTE_MACHINE) \
		RTE_ARCH=$(RTE_ARCH) \
		$(filter-out $(DIRS-y),$(MAKECMDGOALS))

$(TLDK_ROOT)/$(RTE_TARGET)/.config:
	$(Q)mkdir -p $(TLDK_ROOT)/$(RTE_TARGET)/include
	$(Q)cp .config $(TLDK_ROOT)/$(RTE_TARGET)/.config

$(TLDK_ROOT)/$(RTE_TARGET)/include/rte_config.h:
	$(Q)cp -f $(DPDK_ROOT)/config/rte_config.h $(TLDK_ROOT)/$(RTE_TARGET)/include/rte_config.h