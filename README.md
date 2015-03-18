# Mac9P #

**Mac9P** is a software that allows you to mount [9P](http://en.wikipedia.org/wiki/9P ) file systems on a Mac OS X system.

## Install ##
Install the Mac9P.pkg from the Mac9P.dmg.
 
## Uninstall ##

Run **Uninstall.tool** from the Mac9P.dmg.

## Building ##
### Prerequisites ###
* **Xcode**.
* **libutil** headers  (`make installhdrs`): http://opensource.apple.com/ .
* **PackageMaker**  to create the installer from _Auxiliary_tools_ for Xcode.

###  Compiling ###
In a terminal run:
```
#!sh

cd mac9
make all

```


## Mounting ##
### From the Finder ###
**Go** -> **Connect to Server...**: _9p://sources.cs.bell-labs.com_.
### From a Terminal ###


```
#!sh

mkdir /tmp/sources
mount -t 9p sources.cs.bell-labs.com /tmp/sources

```


## Documentation ##
See **mount_9p(8)**.