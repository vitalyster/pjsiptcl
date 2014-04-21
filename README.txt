
Tcl interface to the pjsip client lib.
It links statically to the pjsip library. 

Copyright (c) 2006 Mats Bengtsson
Copyright (c) 2006 Antonio F. Cano Damas (antoniofcano@grupoikusnet.com)

GPL license

What is this:

PSJSIP-TCL is a bind library for implementing a SIP User Agent (SoftPhone) using the PJSIP library (http://www.pjsip.org/).

This library builds with the SVN version (svn co http://anonymous@svn.pjproject.net/repos/pjproject/trunk  pjproject).

You have to copy the pjsiptcl directory into the pjproject one.

Debian dependencies:
	tcl8.4-dev
	tcllib
	tclthread

Compile:
	./configure --with-tcl=/usr/lib/tcl8.4
	make
[Note: /usr/lib/tcl8.4 is the directory where is located the tclConfig.sh script]

MacOSX: ProjectBuilder project 
Windows: Dev-C++ (Bloodshed) project

Usage:

    pjsip::devices input|output ?-current?
        returns a list {name deviceID} if -current
	else lists all devices as {{name deviceID} ...}

    pjsip::setdevices input|output deviceID
	Sets de input or output device

    pjsip::level input|output ?level?
        sets or gets the respective levels with -128 < level < 127

    pjsip::register username password hostname
        Returns the session id.

    pjsip::unregister sessionID

    pjsip::callerid name num
        sets a new caller id, user agent has to be registered before.

    pjsip::dial sip:SipURI
        dials a sip URI (username@domain)

    pjsip::hangup
        hang up current call

    pjsip::answer
        answer call

    pjsip::reject
        reject current call

    pjsip::hold

    pjsip::unhold

    pjsip::state
	Gets Debug info with the state of the User Agent

    pjsip::sendtext text
	Sends a Text message to the current call, using SIP Simple.

    pjsip::sendtone tone
	Sends a DTMF tone, wich is any single character from the set 123A456B789C*0#D

    pjsip::startring
	Plays Ring tone

    pjsip::stoptring
	Stops Ring tone playing

    pjsip::notify eventType ?tclProc?
        sets or gets a notfier procedure for an event type.
	The valid types and callback forms are:
	<Text>          'procName From Text'
	<Media>		'procName callNo accountID mediaState durationSec remoteInfo localInfo'
	<State>         'procName callNo callID State LastState'	               
	<Incoming>	'procName callNo accountID remoteInfo localInfo
	<Registration>  'procName accountId'

	It returns the present tclProc if any. If you specify an empty
	tclProc the callback will be removed.

By default this is the audio codec priority: speex/16000, speex/8000, g711, gsm, l16 and ilbc

A state is a list with any of: CALLING, INCOMING, EARLY, CONNECTING, {CONFIRMED }, DISCONNCTD
Last state: Ringing, Trying, OK, Decline, {Normal call clearing}, {Request Terminated}

A mediaState is a list with any of: active, inactive, hold_local, hold_remote

-----
TODO
-----
	- Transfer. [High]
	- Make more flexible than now the configuration of an user agent account. [High]
	- CallBack, for UV meter. <Levels>        'procName in out'. [Medium]
	- Recording Media. [Low]
	- Handle more than one simultaneus call. [Low]
	- Multiconference (Bridge) conference calls. [Low]
	- IM/Presence buddy functions. [On hold]
