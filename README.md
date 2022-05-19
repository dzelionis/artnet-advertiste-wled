# -artnet_advertise
Artnet/DMX  advertise POOL  packets for  other devices, would work with Soundswitch/Wled/Resolume and other software...

Has ip stuff fixed, cpu utilization inprovemnt and more aggressive on send POOL packets - if not receiving anything...
Fakes/emulates POOL responses for devices which is not supporting POOL replay.
as input takes a list of ip's which needs to be emulated.....(settings in very top of script file)

requires arnet udp port on the machine is running, so if you use few applications, you would need few network addapters to same network....
tested on windows/linux

added Autodiscovery for wled nodes....

Example of wled devices picked up by soundswitch on pc or Denon DJ hardware such as Prime4 using artnet:
![162795983-404c6653-ca04-413f-a1f0-bfe1156f4f45](https://user-images.githubusercontent.com/41810641/169350926-30de440a-89ab-473a-a00f-d007b69fe7da.png)

Final configuration tweaks to make WLED work in "Effect mode", you would have contol of effect, speed, color using attribute flag in sound switch.
![162794864-2bb994d2-0683-4829-b67c-9973fafe42e8](https://user-images.githubusercontent.com/41810641/169350928-1194e99c-b823-4c44-a9a4-ca4656dcad61.png)

Example of attribute use in sound switch to control wleds effect properties:
![image](https://user-images.githubusercontent.com/41810641/169354746-960ad703-395e-4000-a595-8516c80a514f.png)




If you ask why? I am an engineer (network), and DJ+lightning is my hobby where i like to spend my spare time, some videos of my DIY lights...:
https://drive.google.com/drive/folders/1wTOyHKRTKP8_p7d73bdmYTKmweb978kM?usp=sharing

Enjoy
