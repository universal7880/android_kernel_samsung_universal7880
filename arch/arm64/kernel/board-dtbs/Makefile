# Keep the board catalogue separate from the bootloader's DTBH image.
dtb-src := $(wildcard $(srctree)/arch/arm64/boot/dts/exynos7880-a[57]y17lte_eur_open_*.dts) \
	$(wildcard $(srctree)/arch/arm64/boot/dts/exynos7880-a5y17lte_can_open_*.dts) \
	$(wildcard $(srctree)/arch/arm64/boot/dts/exynos7880-a[57]y17lte_kor_all_*.dts)
dtb-y := $(notdir $(dtb-src:.dts=.dtb)) exynos7880-bootstrap.dtb
obj-y := $(dtb-y:.dtb=.dtb.o)
targets += $(dtb-y) $(dtb-y:.dtb=.dtb.S)

$(addprefix $(obj)/,$(dtb-y)): $(obj)/%.dtb: $(srctree)/arch/arm64/boot/dts/%.dts FORCE
	$(call if_changed_dep,dtc)

# Eight-byte alignment is also used by the catalogue reader.
quiet_cmd_board_dtb = DTB     $@
cmd_board_dtb = (echo '.section .dtb.init.rodata,"a"'; \
	echo '.balign 8'; echo '.incbin "$<"'; echo '.balign 8') > $@

$(addprefix $(obj)/,$(dtb-y:.dtb=.dtb.S)): $(obj)/%.dtb.S: $(obj)/%.dtb
	$(call cmd,board_dtb)

$(addprefix $(obj)/,$(obj-y)): $(obj)/%.dtb.o: $(obj)/%.dtb.S FORCE
	$(call if_changed_dep,as_o_S)
