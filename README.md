# Mac9P 1.1 #

**Mac9P** is a software that allows you to mount [9P](http://en.wikipedia.org/wiki/9P ) file systems on a Mac OS X system.

## Install ##
Run **Install Mac9P** from the **Mac9P.dmg**.
 
## Uninstall ##

Run **Uninstall.tool** from the **Mac9P.dmg**.

## Building ##
### Prerequisites ###
* **Xcode**.

###  Compiling ###
In a terminal run:
```
cd mac9
make all

```


## Mounting ##
### From the Finder ###
_(Broken if the binary is not signed)
**Go** -> **Connect to Server...**: _9p://sources.cs.bell-labs.com_.
### From a Terminal ###


```
mkdir /tmp/sources
mount -t 9p -onoauth sources.cs.bell-labs.com /tmp/sources

```


## Documentation ##
See **mount_9p(8)**.

## Troubleshooting ##
### Disable kext signing check ###

1. Boot into Recovery Mode by restarting your mac while holding down _Command+R_.
2. Open a Terminal from **Utilities** -> **Terminal** and run:
```
csrutil disable
csrutil enable --without kext
```
