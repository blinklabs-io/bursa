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
# NETWORK fixes the one network whose profiles the image provisions and
# serves: testnet (network id 0, the default, every testnet) or mainnet
# (network id 1). A mainnet image also needs CHAIN, the one chain whose
# profiles ("name@<chain>-mainnet") it serves: cardano or prime.
NETWORK ?= testnet
CHAIN ?=

# ramStart (imx6ul package) + 0x10000
TEXT_START := 0x80010000

GOENV := GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARM=7 GOARCH=arm
LDFLAGS := -s -w -T $(TEXT_START) -R 0x1000
GOFLAGS = -trimpath -ldflags "$(LDFLAGS)"
TAGS :=
ifeq ($(NETWORK),mainnet)
ifeq ($(TESTNET),1)
$(error TESTNET=1 adds bring-up key tests and an unfiltered /sign endpoint; a mainnet image must not)
endif
ifeq ($(filter $(CHAIN),cardano prime),)
$(error NETWORK=mainnet needs CHAIN=cardano or CHAIN=prime)
endif
TAGS += mainnet
LDFLAGS += -X main.chain=$(CHAIN)-mainnet
else ifneq ($(NETWORK),testnet)
$(error NETWORK must be testnet or mainnet)
else ifneq ($(CHAIN),)
$(error CHAIN applies only to NETWORK=mainnet; a testnet image serves every testnet)
endif
ifeq ($(TESTNET),1)
TAGS += testnet
endif
ifeq ($(PROVISION),1)
ifeq ($(TESTNET),1)
$(error TESTNET=1 adds an unfiltered /sign endpoint; the provisioning image must not sign)
endif
TAGS += provision
APP := armory-provision
endif
ifeq ($(NETWORK),mainnet)
APP := $(APP)-$(CHAIN)-mainnet
endif
ifneq ($(strip $(TAGS)),)
GOFLAGS += -tags $(subst $(space),$(comma),$(strip $(TAGS)))
endif

# FORCE runs the Go build every time: the targets do not depend on the
# build flags, so a TESTNET, PROVISION or NETWORK change would leave an old
# image in place. The Go build cache keeps an unchanged build fast.
.PHONY: all imx clean FORCE

all: $(APP)

imx: $(APP).imx

$(APP): FORCE
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
	rm -f $(foreach a,armory armory-provision $(foreach c,cardano prime,armory-$(c)-mainnet armory-provision-$(c)-mainnet),$(a) $(a).bin $(a).dcd $(a).imx)
