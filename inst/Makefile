NAME=Mac9P
PKG=$(NAME).pkg
DMG=$(NAME).dmg

PKGROOT=/tmp/$(NAME)
KEDIR=$(PKGROOT)/System/Library/Extensions/9p.kext
FSDIR=$(PKGROOT)/System/Library/FileSystems/9p.fs
NPDIR=$(PKGROOT)/System/Library/FileSystems/NetFSPlugins/9p.bundle
MNDIR=$(PKGROOT)/usr/share/man/man8

PKGRESDIR=$(PKG)/Contents/Resources
PKGRESFILES=\
	License.rtf\
	Welcome.rtf\
	InstallationCheck\
	InstallationCheck.strings\
#	background.tiff\

PKGDEP=\
	../kext/9p\
	../mount/mount_9p\
	../load/load_9p\
	../plugin/9p\
	mount_9p.8\
	FSInfo.plist\
	KEInfo.plist\
	NPInfo.plist\
	$(PKGRESFILES)

all: pkg dmg

$(PKG): $(PKGDEP)
	mkdir -p $(KEDIR)/Contents
	cp -pX KEInfo.plist $(KEDIR)/Contents/Info.plist
	mkdir -p $(KEDIR)/Contents/MacOS
	cp -pX ../kext/9p $(KEDIR)/Contents/MacOS/9p
	chmod 644 $(KEDIR)/Contents/MacOS/9p
	mkdir -p $(KEDIR)/Contents/Resources
	cp -pX ../load/load_9p $(KEDIR)/Contents/Resources
	mkdir -p $(FSDIR)/Contents
	cp -pX FSInfo.plist $(FSDIR)/Contents/Info.plist
	mkdir -p $(FSDIR)/Contents/Resources
	cp -pX ../mount/mount_9p $(FSDIR)/Contents/Resources
	mkdir -p $(NPDIR)/Contents
	cp -pX NPInfo.plist $(NPDIR)/Contents/Info.plist
	mkdir -p $(NPDIR)/Contents/MacOS
	cp -pX ../plugin/9p $(NPDIR)/Contents/MacOS/9p
	mkdir -p $(MNDIR)
	cp -pX mount_9p.8 $(MNDIR)
	sudo chown -R root:wheel $(PKGROOT)
	sudo chmod u+s $(KEDIR)/Contents/Resources/load_9p
	/Developer/usr/bin/packagemaker \
		--root $(PKGROOT) \
		--id com.lab-fgb.9p \
		--domain system \
		--no-recommend \
		--root-volume-only \
		--out $@
	cp -pX $(PKGRESFILES) $(PKGRESDIR)
	sudo rm -fr $(PKGROOT)

TDMG=tmp.dmg
VOLUME=/Volumes/$(NAME)
$(DMG): $(PKG) #volume.icns
	hdiutil create -quiet -layout NONE -size 512k -fs HFS+ -volname $(NAME) $(TDMG)
	hdiutil attach -quiet -private -nobrowse $(TDMG)
	cp -pRX $(PKG) $(VOLUME)
#	cp -pX volume.icns $(VOLUME)/.VolumeIcon.icns
#	/Developer/usr/bin/SetFile -a -C $(VOLUME)
	ln -s $(VOLUME)/$(PKGRESDIR)/License.rtf $(VOLUME)/License.rtf
	cp -pX Uninstall.tool $(VOLUME)
#	cp -pX DS_Store $(VOLUME)/.DS_Store
	hdiutil detach -quiet $(VOLUME)
	hdiutil convert -quiet -format UDBZ $(TDMG) -o /tmp/$@
	mv -f /tmp/$@ $@
	rm -f $(TDMG)

clean:
	rm -fr *.dmg *.pkg

dmg: $(DMG)
pkg: $(PKG)
