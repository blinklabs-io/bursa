# Build with the TamaGo toolchain, e.g. on the build host:
#   source ~/tamago/env.sh && make imx

APP := armory
TAMAGO ?= $(HOME)/tamago/usr/local/tamago-go/bin/go

# ramStart (imx6ul package) + 0x10000
TEXT_START := 0x80010000

GOENV := GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARM=7 GOARCH=arm
GOFLAGS := -trimpath -ldflags "-s -w -T $(TEXT_START) -R 0x1000"

.PHONY: all imx clean

all: $(APP)

imx: $(APP).imx

$(APP): *.go ../se050/*.go go.mod
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
