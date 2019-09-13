**JoeFinder**
=============

This script INDICATES if a malcious app is installed on an Android device. It collects the list of installed apps on an Android device, then queries Koodous for each app. Koodous is an awesome online platform, containing millions of analyzed Android apps. Therefore, Koodous queries give a good indication if any of the installed apps is malicious.

Please keep in mind that some malicious apps carry the same package name of benign apps, therefore notice the ratio of detected malicious instances provided by JoeFinder. The higher the ratio, the higher possibility that the installed app is malicious. Additionally, JoeFinder provides links to analysis reports of Koodous for each app (if any exist).

At the end of the day, JoeFinder does not analyze any app. Therefore, its results mainly depend on whether Koodous users think an app (or another one with the same package name) is malicious.... unfortuantely this might give misleading results sometimes :(

This script does not require rooting and it does not install anything on the Android device. After using the script, you can also deactivate USB debuggin on your device (see Requirements)


Requirements
=============
*1) Python3*

*2) Android SDK tools*
Android SDK tools are required to communicate with the Android device. Additionally, the Android device should allow USB communication with your computer.

For an easy guide on installing SDK tools on your computer (Windows/Linux/Mac), as well as allowing USB debugging on Android device, follow this link:

https://www.xda-developers.com/quickly-install-adb/

How to use it
=============

1- Install python3 requirements:
	
	pip3 install -r requirements.txt

2- Connect only one Android device to the computer
3- Run the script

	python3 joefinder.py

