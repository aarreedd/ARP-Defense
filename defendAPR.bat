@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION

ECHO.
IF "%1"=="" (
	ECHO SUMMARY
	ECHO 	Deletes the specified IP from the ARP table, then pings the IP to
	ECHO 	extablish the correct Physical Address.
	ECHO 	The script will then continually monitor the specified IP's entry in
	ECHO 	the ARP table. If the IP's ARP table ever changes or is removed, the
	ECHO 	script will BEEP and set the Physical Address back to the correct value.	
	ECHO AUTHOR
	ECHO 	Alan Reed
	ECHO 	Please contact the author with any questions, comments, or concers
	ECHO 	at alan.william.reed@gmail.com
	ECHO LICENSE
	ECHO 	Copyright 2012. This script is free to use, modify, and redistribute
	ECHO 	so long as you give credit to the original author.
	ECHO SYNTAX
	ECHO 	"defendARP.bat <IPAddr to monitor>"
	ECHO DESCRIPTION
	ECHO 	^<IPAddr to monitor^> should NOT be your own IPAddr. Use the IPAddr
	ECHO 	of a different device on you LAN that you are communicating with. Try
	ECHO 	the IPAddr of your network gateway.
	ECHO.
	GOTO ERROR
)

 :: Check if $1 is Local hosts IP
FOR /F "tokens=2" %%i in ('ARP -A ^| FINDSTR \-\-\-') do (

	IF "%1"=="%%i" (
		ECHO Cannot protect your own IP Address -- Try using the Default Gateway or router's IP Address.
		GOTO ERROR
	)
)


ECHO INITIALIZING...
ECHO.
ECHO Removing %1 from ARP table.
 :: Remove %1 from arp table
ARP -d %1
ECHO OK.

 :: Ping the IP to establish it's correct MAC address.
 :: Note that ARP could still be poisoned if attcker sends poison packet while we are pinging.
ECHO Obtaining MAC address.
PING -n 1 %1 >nul
IF ERRORLEVEL 1 (
	ECHO Bad IP Address.
	GOTO ERROR
)

 :: Find the specified IP in the ARP Table
SET PhysAddr=""
SET tmp=""
FOR /F "tokens=*" %%a in ('ARP -a ^| findstr "%1"') do (
	SET tmp=%%a
 	:: We do this little trick with the question marks to avoid return the wrong line from the ARP table.
	SET tmp=!tmp: =?!
	FOR /F "tokens=*" %%b in ('ECHO !tmp! ^| findstr %1?') do (
		SET PhysAddr=%%b
	)
)
 :: Check that the specified IP was found in the ARP table
IF %PhysAddr%=="" (
	ECHO Host Not Found.
	GOTO ERROR
)
 :: Extract the actualy Physical Address
SET PhysAddr=%PhysAddr:~15,-11%
SET PhysAddr=%PhysAddr:?=%
ECHO OK.

:QUESTION
SET /p  a=Is %PhysAddr% the correct MAC for %1 (y/n)?
IF "%a%"=="n" (
	ECHO.
	ECHO If this is not the correct MAC then you have already been poinsoned.
	ECHO You must start this script in a 'safe' state. 
	arp -d %1
	GOTO DONE
) else IF "%a%"=="y" (
	ECHO OK.
	ECHO.
	ECHO Monitoring your ARP table...
	ECHO.
	SET GoodMAC=%PhysAddr%
	GOTO LOOP
) else ( GOTO QUESTION )

 :: Monitor the ARP Table
:LOOP
	 :: Find the specified IP in the ARP Table
	SET PhysAddr=""
	SET tmp=""
	FOR /F "tokens=*" %%a in ('ARP -a ^| FINDSTR "%1"') do (
		SET tmp=%%a
		SET tmp=!tmp: =?!
		FOR /F "tokens=*" %%b in ('ECHO !tmp! ^| findstr %1?') do (
			SET PhysAddr=%%b
		)
	)
	IF %PhysAddr%=="" (
		ECHO %1 not found. Reestablishing connection...
		ping -n 1 %1 | findstr TTL >nul
		IF ERRORLEVEL 1 ( 
			ECHO Lost Connection to %1
			GOTO ERROR 
		)
		ECHO OK.
		GOTO LOOP
	)
	 :: Extract the Physical Address
	SET PhysAddr=%PhysAddr:~15,-11%
	SET PhysAddr=%PhysAddr:?=%

	 :: check that the MAC did not change
	IF NOT "%GoodMAC%"=="%PhysAddr%" (
		ECHO.
		 :: BEEP - echo <ctrl+g> to a .txt, then copy the result onto the line below
		ECHO  
		ECHO ARP POISONED!
		ECHO Spoofed IP: %1
		ECHO %1's actual Physical Address: %GoodMAC%
		ECHO Attcker's Physical Address: %PhysAddr%
		ECHO Attempting to reset the correct Physical Address...
		 :: Attempt to reset ARP table. This will not work if we are continually being poisoned.
		ARP -d %1
		PING -n 1 %1 >nul
		ECHO ARP Table reset.
		ECHO.
		ECHO Monitoring your ARP table...
	)
	 :: wait for 5 seconds
	ping -n 5 127.0.0.1 >nul
GOTO LOOP

GOTO DONE
:ERROR
ECHO.
:DONE