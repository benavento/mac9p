NAME=Mac9P
PKG=Install\ $(NAME).pkg
DMG=$(NAME).dmg

TMPDIR=/tmp/$(NAME)
PKGROOT=$(TMPDIR)/root
KEDIR=$(PKGROOT)/Library/Extensions/9p.kext
FSDIR=$(PKGROOT)/Library/FileSystems/9p.fs
NPDIR=$(PKGROOT)/Library/FileSystems/NetFSPlugins/9p.bundle
MNDIR=$(PKGROOT)/usr/local/share/man/man8


PKGDEP=\
	../kext/9p\
	../mount/mount_9p\
	../load/load_9p\
	../plugin/9p\
	mount_9p.8\
	FSInfo.plist\
	KEInfo.plist\
	NPInfo.plist\
	License.rtf\
	Welcome.rtf\
	InstallationCheck\
	distribution.xml\
#	background.tiff\

all: pkg dmg

PKGTMP=$(NAME).pkg.tmp
$(PKG): $(PKGDEP)
	echo building $(PKG)
	mkdir -p "$(KEDIR)/Contents"
	cp -pX KEInfo.plist "$(KEDIR)/Contents/Info.plist"
	mkdir -p "$(KEDIR)/Contents/MacOS"
	cp -pX ../kext/9p "$(KEDIR)/Contents/MacOS/9p"
	chmod 644 "$(KEDIR)/Contents/MacOS/9p"
	mkdir -p "$(KEDIR)/Contents/Resources"
	cp -pX ../load/load_9p "$(KEDIR)/Contents/Resources"
	mkdir -p "$(FSDIR)/Contents"
	cp -pX FSInfo.plist "$(FSDIR)/Contents/Info.plist"
	mkdir -p "$(FSDIR)/Contents/Resources"
	cp -pX ../mount/mount_9p "$(FSDIR)/Contents/Resources"
	mkdir -p "$(NPDIR)/Contents"
	cp -pX NPInfo.plist "$(NPDIR)/Contents/Info.plist"
	mkdir -p "$(NPDIR)/Contents/MacOS"
	cp -pX ../plugin/9p "$(NPDIR)/Contents/MacOS/9p"
	mkdir -p "$(MNDIR)"
	cp -pX mount_9p.8 "$(MNDIR)"
	chmod u+s "$(KEDIR)/Contents/Resources/load_9p"
	mkdir -p "$(TMPDIR)/Scripts"
	cp -pX InstallationCheck "$(TMPDIR)/Scripts"
	pkgbuild \
		--root "$(PKGROOT)" \
		--identifier com.lab-fgb.9p \
		--install-location "/" \
		--ownership recommended "$(PKGTMP)"
	productbuild \
		--identifier com.lab-fgb.9p \
		--resources ./ \
		--scripts "$(TMPDIR)/Scripts" \
		--package-path "$(PKGTMP)" \
		--distribution distribution.xml \
		"$@"
	rm -fr "$(PKGTMP)" "$(TMPDIR)"

DMGFILES=\
	$(PKG)\
	License.rtf\
	Uninstall.tool\

DMGDEP=\
	$(DMGFILES)\
	DS_Store\
#	VolumeIcon.icns\

TDMG=tmp.dmg
VOLUME=/Volumes/$(NAME)
$(DMG): $(DMGDEP)
	hdiutil create -quiet -layout NONE -size 512k -fs HFS+ -volname "$(NAME)" "$(TDMG)"
	hdiutil attach -quiet -private -nobrowse "$(TDMG)"
	cp -pX $(DMGFILES) "$(VOLUME)"
	# hide extension
	SetFile -a E $(VOLUME)/$(PKG) $(VOLUME)/License.rtf
#	cp -pX VolumeIcon.icns "$(VOLUME)/.VolumeIcon.icns"
#	SetFile -a -C "$(VOLUME)"
	cp -pX DS_Store "$(VOLUME)/.DS_Store"
	hdiutil detach -quiet "$(VOLUME)"
	hdiutil convert -quiet -format UDBZ "$(TDMG)" -o "$@"
	rm -f $(TDMG)

clean:
	rm -fr *.dmg *.pkg *.tmp

dmg: $(DMG)
pkg: $(PKG)
