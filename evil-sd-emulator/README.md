## Overview:

By default, this simple program will pretend to be a WiFi SD card. It can push arbitrary files (in the form of a FAT disk image) to the Android app.

You only need to be on the same LAN as the app user.

See the "CONFIG" section of the code for basic setup.

## Attacks:

### DoS

It looks like the developers of the app were going to add a webserver to it. They stopped half way through, but left some of the code behind. Any attempts to connect to this webserver cause the app to crash due to a null dereference.

This attack simply makes a request to the broken webserver whenever the app is detected, killing the entire app.

### Password stealing

If we tell the app that the authentication details are incorrect, it will prompt the user for another username and password. We can harvest anything the user enters in plaintext...
