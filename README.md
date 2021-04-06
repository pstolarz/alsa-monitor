# ALSA Monitor

This tool monitors ALSA control events for installed sound card(s). It's enhanced
version of the standard Linux `alsactl-monitor` tool with more detailed output
as shown below. The tool had been used to debug ALSA drivers and PulseAudio issues
on the Linux platform.

`alsactl-monitor` output:
```
$ alsactl monitor
node hw:0, #60 (3,7,0,ELD,0) VALUE INFO
node hw:0, #55 (0,0,0,HDMI/DP,pcm=7 Jack,0) VALUE
node hw:0, #60 (3,7,0,ELD,0) VALUE INFO
node hw:0, #55 (0,0,0,HDMI/DP,pcm=7 Jack,0) VALUE
```

This monitor:
```
$ ./alsa-monitor 
hw:0 event:
  mask: 0x00000003 (value,info)
  element:
    numid: 60
    iface: 3 (PCM)
    dev: 7
    subdev: 0
    name: 'ELD'
    index: 0
  info:
    access: read,volatile
    count: 0
    type: 4 (BYTES)

hw:0 event:
  mask: 0x00000001 (value)
  element:
    numid: 55
    iface: 0 (CARD)
    dev: 0
    subdev: 0
    name: 'HDMI/DP,pcm=7 Jack'
    index: 0
  info:
    access: read
    count: 1
    type: 1 (BOOLEAN)
  bool(s):
    false

hw:0 event:
  mask: 0x00000003 (value,info)
  element:
    numid: 60
    iface: 3 (PCM)
    dev: 7
    subdev: 0
    name: 'ELD'
    index: 0
  info:
    access: read,volatile
    count: 36
    type: 4 (BYTES)
  byte(s):
    10:00:08:00:6c:10:00:01 00:00:00:00:00:00:00:00
    1e:6d:f9:76:4c:47:20:55 4c:54:52:41:57:49:44:45
    09:07:07:00

hw:0 event:
  mask: 0x00000001 (value)
  element:
    numid: 55
    iface: 0 (CARD)
    dev: 0
    subdev: 0
    name: 'HDMI/DP,pcm=7 Jack'
    index: 0
  info:
    access: read
    count: 1
    type: 1 (BOOLEAN)
  bool(s):
    true
```

## Build
`libasound` library (development version) is required to be installed first:
```
sudo apt-get install libasound2-dev
```
Then make the monitor:
```
make
```

## License
GNU GENERAL PUBLIC LICENSE v2 (as for `alsactl-monitor` this tool bases on).
