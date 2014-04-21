# Simple iax phone.

package require pjsip
package require tile

set registrar sip:fwd.pulver.com
set useruri sip:823359@fwd.pulver.com
set realm fwd.pulber.com
set user fwdnumber
set pass passwprd
set stun stun.softjoys.com
set number sip:613@fwd.pulver.com

proc NotifyRegister {id} {
    puts "NotifyRegister: $id"
    set ::cb(reg) "Reg: $id"
}
proc NotifyState {callNo  callID state args} {
    puts "NotifyState $args"
    set ::cb(state) "State: $state"
}
proc NotifyIncoming {callNo  callID remoteInfo args} {
    puts "NotifyIncoming $args"
    set ::cb(incoming) "Incoming: $remoteInfo"
}
proc NotifyMedia {args} {
    puts "NotifyMedia: $args"
}
::pjsip::notify <Registration> NotifyRegister
::pjsip::notify <State>        NotifyState
::pjsip::notify <Media>        NotifyMedia

proc Register {} {
    set ::session [::pjsip::register $::registrar $::useruri $::realm $::user $::pass $::stun]
}
proc UnRegister {} {
    ::pjsip::unregister
}
proc Dial {} {
    ::pjsip::dial ${::number}
}
proc HangUp {} {
    ::pjsip::hangup   
}
proc MicCmd {level} {
    ::pjsip::level input [expr $level/100.0]
}
proc SpeakerCmd {level} {
    ::pjsip::level output [expr $level/100.0]    
}
set cb(reg) "Reg:"
set cb(state) "State:"
set cb(incoming) "Incoming:"
set vol(mic) 100
set vol(spk) 100
set vol(mic) [expr 100*[::pjsip::level input]]
set vol(spk) [expr 100*[::pjsip::level output]]

# UI:
toplevel .phone
wm title .phone "SIP Phone"
wm resizable .phone 0 0
set w .phone.pad.top
pack [ttk::frame .phone.pad -padding {16 10}]
pack [ttk::frame $w] -side top
ttk::label $w.tit -text "Simple IAX Phone" -padding {0 4 0 8}
ttk::entry $w.num -textvariable number
ttk::button $w.dial -text Dial -command Dial
ttk::button $w.hang -text HangUp -command HangUp
ttk::button $w.reg  -text Register -command Register
ttk::button $w.ureg -text UnRegister -command UnRegister
ttk::button $w.acc  -text "Account Info" -command SetAccount
ttk::label $w.lreg  -textvariable cb(reg)
ttk::label $w.lstat -textvariable cb(state)
ttk::label $w.lincoming -textvariable cb(incoming)

grid  $w.tit    -
grid  $w.num    -        -sticky ew -pady 2
grid  $w.dial   $w.hang  -sticky ew -padx 4 -pady 2
grid  $w.reg    $w.ureg  -sticky ew -padx 4 -pady 2
grid  $w.acc    -        -sticky ew -pady 2
grid  $w.lreg   -        -sticky w  -pady 2
grid  $w.lstat  -        -sticky w  -pady 2
grid  $w.lincoming  -        -sticky w  -pady 2
grid columnconfigure $w 0 -uniform u
grid columnconfigure $w 1 -uniform u

set w .phone.pad.vol
pack [ttk::frame $w] -side top
ttk::label $w.lmic -text Microphone:
ttk::label $w.lspk -text Speakers:
ttk::scale $w.smic -orient horizontal -from 0 -to 100 \
  -variable vol(mic) -command MicCmd
ttk::scale $w.sspk -orient horizontal -from 0 -to 100 \
  -variable vol(spk) -command SpeakerCmd
ttk::progressbar $w.pmic -orient horizontal -variable lev(mic)
ttk::progressbar $w.pspk -orient horizontal -variable lev(spk)

grid  $w.lmic  $w.smic  -sticky e -padx 4 -pady 2
grid  x        $w.pmic  -sticky ew
grid  $w.lspk  $w.sspk  -sticky e -padx 4 -pady 2
grid  x        $w.pspk  -sticky ew
grid columnconfigure $w 1 -weight 1

proc SetAccount {} {
    set w .phone_account
    toplevel $w
    wm title $w "Account Info"
    wm resizable $w 0 0
    set box $w.pad.top
    pack [ttk::frame $w.pad -padding {16 10}]
    pack [ttk::frame $box] -side top

    ttk::label $box.registrar -text "Registrar URI:"
    ttk::label $box.useruri -text "User URI:"
    ttk::label $box.realm -text "Realm:"
    ttk::label $box.user -text "Username:"
    ttk::label $box.pass -text "Password:"
    ttk::label $box.stun -text "STUN URI:"

    ttk::entry $box.eregistrar -textvariable ::registrar
    ttk::entry $box.euseruri -textvariable ::useruri
    ttk::entry $box.erealm -textvariable ::realm
    ttk::entry $box.euser -textvariable ::user
    ttk::entry $box.epass -textvariable ::pass
    ttk::entry $box.estun -textvariable ::stun
    
    grid  $box.registrar  $box.eregistrar  -pady 2
    grid  $box.useruri  $box.euseruri  -pady 2
    grid  $box.realm  $box.erealm  -pady 2
    grid  $box.user  $box.euser  -pady 2
    grid  $box.pass  $box.epass  -pady 2
    grid  $box.stun  $box.estun  -pady 2
    grid $box.registrar  $box.useruri  $box.realm $box.user  $box.pass  $box.stun  -sticky e
    grid $box.eregistrar  $box.euseruri  $box.erealm $box.euser  $box.epass  $box.estun -sticky ew

    set bot $w.pad.bot
    pack [ttk::frame $bot -padding {4 6}] -fill x
    ttk::button $bot.set -text Set -command [list destroy $w]
    pack $bot.set -side right
}
