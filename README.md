# -artnet_advertise
Artnet/DMX  advertise POOL  packets for  other devices, would work with Soundswitch/Wled etc...

Has ip stuff fixed, cpu utilization inprovemnt and more aggressive on send POOL packets - if not receiving anything...
Fakes/emulates POOL responses for devices which is not supporting POOL replay.
as input takes a list of ip's which needs to be emulated.....(settings in very top of script file)

requires arnet udp port on the machine is running, so if you use few applications, you would need few network addapters to same network....
tested on windows/linux

