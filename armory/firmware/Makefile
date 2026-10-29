# Build with the TamaGo toolchain, e.g. on the build host:
#   source ~/tamago/env.sh && make imx

APP := armory
empty :=
space := $(empty) $(empty)
comma := ,
TAMAGO ?= $(HOME)/tamago/usr/local/tamago-go/bin/go
# TESTNET=1 adds the bring-up key tests and the unfiltered /sign endpoint;
# never use it for a device holding keys that matter
TESTNET ?= 0
# PROVISION=1 builds the provisioning image: key import, profiles, the reward
# account, the opcert floor and reset, and no signing. The default image
# signs and serves no provisioning endpoint.
PROVISION ?= 0

# ramStart (imx6ul package) + 0x10000
TEXT_START := 0x80010000

GOENV := GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARM=7 GOARCH=arm
GOFLAGS := -trimpath -ldflags "-s -w -T $(TEXT_START) -R 0x1000"
TAGS :=
ifeq ($(TESTNET),1)
TAGS += testnet
endif
ifeq ($(PROVISION),1)
TAGS += provision
APP := armory-provision
endif
ifneq ($(strip $(TAGS)),)
GOFLAGS += -tags $(subst $(space),$(comma),$(strip $(TAGS)))
endif

.PHONY: all imx clean

all: $(APP)

imx: $(APP).imx

$(APP): *.go ../se050/*.go ../profile/*.go ../policy/*.go ../device/*.go go.mod
	$(GOENV) $(TAMAGO) build $(GOFLAGS) -o $(APP)

$(APP).dcd: TAMAGO_PKG=$(shell $(GOENV) $(TAMAGO) list -m -f '{{.Dir}}' github.com/usbarmory/tamago)
$(APP).dcd: go.mod
	cp -f $(TAMAGO_PKG)/board/usbarmory/mk2/imximage.cfg $(APP).dcd

$(APP).bin: $(APP)
	arm-none-eabi-objcopy --remove-section=.debug* --remove-section=.note* \
	    --set-section-flags .bss=alloc,load,contents \
	    --set-section-flags .noptrbss=alloc,load,contents \
	    $(APP) -O binary $(APP).bin

$(APP).imx: $(APP).bin $(APP).dcd
	mkimage -n $(APP).dcd -T imximage -e $(TEXT_START) -d $(APP).bin $(APP).imx
	# copy the entry point from the ELF header
	dd if=$(APP) of=$(APP).imx bs=1 count=4 skip=24 seek=4 conv=notrunc

clean:
	rm -f $(APP) $(APP).bin $(APP).dcd $(APP).imx
