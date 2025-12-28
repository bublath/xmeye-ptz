This is a small example Code in Perl that allows to send PTZ commands to my XMEye PTZ Camera.
It's not really possible to identify the model or say what other cameras work the same way.
However the firmware is: V5.00.R02.000807AB.10010.346617.0000000

As the camera uses a RSA key exchange and encrypted commands, it took me a while (with the help of AI) to reverse engineer this from Wireshark traces, Browser logs and examination of Javascript fragments.
The result is a script that can send the Camera to Preset position 1, which should give others the option to modify this to use different commands.
Hint: In developer Mode in the Browser (F12) the console shows details of how the JSON calls need to look like in order to use the commands.

Call syntax is

`perl xmeye-ptz --ip <ip adress of camera> --pw <password of admin user> --debug [0|1]`

This code does not at all adress the transfer of live streams which work over websockets, but as these are probably encrypted the same way, it may be a basis for others to develop something.
