# websockify C

Websockify is a WebSocket to TCP proxy/bridge. This allows a browser to connect
to any application/server/service.

This is the continuation of the abandoned C version of the websockify project.
See: [novnc/websockify](https://github.com/novnc/websockify)

## How to build

Get the sources:

```
git pull https://github.com/tenchman/websockify.git
```

Build:

```
cd websockify
mkdir build
cd build
cmake ..
make
sudo make install
```
