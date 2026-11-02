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
# WIPE=1 builds the wipe image: it removes a profile and its keys, every key
# and profile, or the signing log head, on request, and neither signs nor
# provisions.
WIPE ?= 0
# NETWORK fixes the one network whose profiles the image provisions and
# serves: testnet (network id 0, the default, every testnet) or mainnet
# (network id 1). A mainnet image also needs CHAIN, the one chain whose
# profiles ("name@<chain>-mainnet") it serves: cardano or prime.
NETWORK ?= testnet
CHAIN ?=

# HAB_KEYS=<dir> also signs each image with high assurance boot (HABv4) into
# <image>-signed.imx; unset, the build and its output are unchanged. The
# directory holds the keys made by habtool, see README.md: CSF_<n>_key.pem,
# CSF_<n>_crt.pem, IMG_<n>_key.pem, IMG_<n>_crt.pem and SRK_1_2_3_4_table.bin,
# n being HAB_SRK_INDEX. Keep the production keys offline; this Makefile only
# reads them.
HAB_KEYS ?=
# HABTOOL is crucible's habtool: go install github.com/usbarmory/crucible/cmd/habtool@latest
HABTOOL ?= habtool
# HAB_SRK_INDEX picks which of the four SRK table keys (1-4) issued the CSF
# and IMG certificates; their files carry the same number.
HAB_SRK_INDEX ?= 1
# HAB_SDP=1 signs for loading over USB in recovery mode (serial download),
# written to <image>-signed-sdp.imx. The default signs for the internal flash
# and memory cards.
HAB_SDP ?= 0
# HAB_ALLOW_TESTNET=1 lets HAB_KEYS sign a TESTNET=1 image, written to
# <image>-testnet-signed.imx. Such an image serves an unfiltered /sign
# endpoint.
HAB_ALLOW_TESTNET ?= 0

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
ifeq ($(WIPE),1)
ifneq ($(PROVISION)$(TESTNET),00)
$(error WIPE=1 builds an image that only deletes; it takes neither PROVISION=1 nor TESTNET=1)
endif
TAGS += wipe
APP := armory-wipe
endif
ifeq ($(NETWORK),mainnet)
APP := $(APP)-$(CHAIN)-mainnet
endif
ifneq ($(strip $(TAGS)),)
GOFLAGS += -tags $(subst $(space),$(comma),$(strip $(TAGS)))
endif

ifneq ($(HAB_KEYS),)
ifeq ($(TESTNET),1)
ifneq ($(HAB_ALLOW_TESTNET),1)
$(error refusing to HAB-sign a TESTNET=1 image: it serves an unfiltered /sign endpoint, and a boot-signed image would run on boards holding keys that matter. Set HAB_ALLOW_TESTNET=1 only for a board that holds no such keys)
endif
$(warning WARNING: HAB-signing a TESTNET=1 image; it serves an unfiltered /sign endpoint. Never run it on a board that holds mainnet profiles)
endif
ifneq ($(words $(HAB_SRK_INDEX)),1)
$(error HAB_SRK_INDEX must be 1, 2, 3 or 4)
endif
ifeq ($(filter 1 2 3 4,$(HAB_SRK_INDEX)),)
$(error HAB_SRK_INDEX must be 1, 2, 3 or 4)
endif
endif
# A signed TESTNET=1 image never takes the name of the signed signing image.
HAB_SIGNED := $(APP)$(if $(filter 1,$(TESTNET)),-testnet)-signed
ifeq ($(HAB_SDP),1)
HAB_SIGNED := $(HAB_SIGNED)-sdp
HAB_SDP_FLAG := -s
else
HAB_SDP_FLAG :=
endif

# FORCE runs the Go build every time: the targets do not depend on the
# build flags, so a TESTNET, PROVISION or NETWORK change would leave an old
# image in place. The Go build cache keeps an unchanged build fast.
.PHONY: all imx clean FORCE

all: $(APP)

imx: $(APP).imx $(if $(HAB_KEYS),$(HAB_SIGNED).imx)

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

# The CSF is appended to the unsigned image, whose IVT it is signed against.
$(HAB_SIGNED).imx: $(APP).imx
	rm -f $@ $(HAB_SIGNED).csf
	@for f in CSF_$(HAB_SRK_INDEX)_key.pem CSF_$(HAB_SRK_INDEX)_crt.pem IMG_$(HAB_SRK_INDEX)_key.pem IMG_$(HAB_SRK_INDEX)_crt.pem SRK_1_2_3_4_table.bin; do \
	    test -f "$(HAB_KEYS)/$$f" || { echo "missing $(HAB_KEYS)/$$f"; exit 1; }; \
	done
	@command -v $(HABTOOL) >/dev/null || { echo "$(HABTOOL) not found; see README.md"; exit 1; }
	$(HABTOOL) \
	    -A $(HAB_KEYS)/CSF_$(HAB_SRK_INDEX)_key.pem \
	    -a $(HAB_KEYS)/CSF_$(HAB_SRK_INDEX)_crt.pem \
	    -B $(HAB_KEYS)/IMG_$(HAB_SRK_INDEX)_key.pem \
	    -b $(HAB_KEYS)/IMG_$(HAB_SRK_INDEX)_crt.pem \
	    -t $(HAB_KEYS)/SRK_1_2_3_4_table.bin \
	    -x $(HAB_SRK_INDEX) $(HAB_SDP_FLAG) \
	    -i $(APP).imx \
	    -o $(HAB_SIGNED).csf
	cat $(APP).imx $(HAB_SIGNED).csf > $@

clean:
	rm -f $(foreach a,armory armory-provision armory-wipe $(foreach c,cardano prime,armory-$(c)-mainnet armory-provision-$(c)-mainnet armory-wipe-$(c)-mainnet),$(a) $(a).bin $(a).dcd $(a).imx $(foreach s,signed signed-sdp testnet-signed testnet-signed-sdp,$(a)-$(s).imx $(a)-$(s).csf))
