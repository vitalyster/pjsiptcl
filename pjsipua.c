/* 
 * pjsipua.c
 *
 *  Tcl interface to the pjsua sip client lib.
 *
 * Copyright (c) 2006 Mats Bengtsson (matben@privat.utfors.se)
 * Copyright (c) 2006 Antonio Cano Damas (antoniofcano@grupoikusnet.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#define DEBUG		1
#define DEBUG_LEVEL	5
#define LOG_FILE	"./pjsiptcl.log"
#define THIS_FILE	"pjsipua.c"
#define NO_LIMIT	(int)0x7FFFFFFF

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* On 10.2.8 box I need this fix. */
#if TARGET_API_MAC_CARBON
    typedef int socklen_t;
#endif

#include <pjsua.h>

/* thread support */
#if defined(WIN32)  ||  defined(_WIN32_WCE)
// empty
#else
#	include <pthread.h>
#endif

#if TARGET_API_MAC_CARBON
#	include <Tcl/tcl.h>
#else
#	include "tcl.h"
#endif

#define PACKAGE_VERSION "0.1"
#define USE_THREAD_EVENTS_METHOD 1

#define MAX_CALLS 3

/* Structures and needed variables for the User Agent config */
struct call_data
{
    pj_timer_entry	    timer;
};


static struct app_config
{
    pjsua_config			cfg;
    pjsua_logging_config    log_cfg;
    pjsua_media_config	    media_cfg;
    pjsua_transport_config  udp_cfg;
    pjsua_transport_config  rtp_cfg;
	
	pjsua_acc_config		account_cfg;
    struct call_data		call_data[MAX_CALLS];
	unsigned				duration;
    pj_pool_t				*pool;
	unsigned				input_dev;
	unsigned				output_dev;

    float					mic_level;
	float					speaker_level;
} app_config;

static struct app_ring_tone
{
    pj_pool_t			*pool;
	pjmedia_port		*current_tone;
    pjsua_conf_port_id  port;
} app_ring_tone;

static char *dtmf_tones = "123A456B789C*0#D";	/* valid touch tones */

/* State variables of the User Agent */
static pjsua_acc_id		current_acc;
static pjsua_call_id	current_call = PJSUA_INVALID_ID;

/* Init/Exit functions */
DLLEXPORT int	Pjsiptcl_Init(Tcl_Interp *interp);
DLLEXPORT int	Pjsiptcl_SafeInit(Tcl_Interp *interp );
static void		ExitHandler(ClientData clientData);

/* Command functions */
static int		AnswerObjCmd( ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[] );
static int 		DialObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int 		DevicesObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		SetDevicesObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		HangUpObjCmd( ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[] );
static int      HoldObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		LevelObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		NotifyObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int 		RegisterObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		RejectObjCmd( ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[] );
static int 		SendTextObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		SendToneObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int 		StateObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		StartRingObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		StopRingObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int      UnholdObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int      UnregisterObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);

static int		ConfListObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		ConfUnlinkObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);
static int		ConfLinkObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]);

/* Event Callback functions */
static void		PollEvents(ClientData clientData);
static void 	EventMediaState(pjsua_call_id call_id);
static void 	EventCallState(pjsua_call_id call_id, pjsip_event *e);
static void 	EventIncomingCallState(pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data *rdata);
static void 	EventRegistration(pjsua_acc_id acc_id);
static void 	EventText(pjsua_call_id call_id, const pj_str_t *from, const pj_str_t *to, const pj_str_t *contact, const pj_str_t *mime_type, const pj_str_t *text);
static void		call_timeout_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry);

/* 
 * These arrays MUST be kept in sync!
 */
static Tcl_Obj *sNotifyRecord[] = {
    NULL,		/* Text 		*/
    NULL,		/* Media 		*/
    NULL,		/* State 		*/
    NULL,		/* Incoming 	*/
    NULL		/* Registration */
};

enum {
    kNotifyCmdText  		= 0L, 
    kNotifyCmdMedia,
    kNotifyCmdState,
    kNotifyCmdIncoming,
    kNotifyCmdRegistration
};

CONST char *notifyCmd[] = {
    "<Text>", 
    "<Media>",
    "<State>", 
    "<Incoming>",
    "<Registration>",
    (char *) NULL
};

CONST char *devicesCmd[] = {
    "input", 
    "output", 
    (char *) NULL
};
enum {
    kPjsipInput                = 0L, 
    kPjsipOutput
};

/* Thread Stuff */
#if 0	// Just as a backup
static void 	EvalScriptAsync(Tcl_Obj *cmdObj);
#endif
  
#if USE_THREAD_EVENTS_METHOD
extern void XThread_RegisterThread(Tcl_Interp *interp);
extern void XThread_UnregisterThread();
extern void XThread_EvalInThread(Tcl_ThreadId threadId, const char *script, int flags);
#endif

#define kNotifyCallbackCacheSize 4096
static char asyncCallbackCache[kNotifyCallbackCacheSize];

static Tcl_TimerToken sTimerToken = NULL;
static Tcl_ThreadId sMainThreadID;
#define kTimerPollEventsMillis 100

/* os-dependent macros, etc. From iaxclient. */
#if defined(WIN32)  ||  defined(_WIN32_WCE)
#include <windows.h>
#define MUTEX CRITICAL_SECTION
#define MUTEXINIT(m) InitializeCriticalSection(m)
#define MUTEXLOCK(m) EnterCriticalSection(m)
#define MUTEXUNLOCK(m) LeaveCriticalSection(m)
#define MUTEXDESTROY(m) DeleteCriticalSection(m)
#else
#define MUTEX pthread_mutex_t
#define MUTEXINIT(m) pthread_mutex_init(m, NULL) //TODO: check error
#define MUTEXLOCK(m) pthread_mutex_lock(m)
#define MUTEXUNLOCK(m) pthread_mutex_unlock(m)
#define MUTEXDESTROY(m) pthread_mutex_destroy(m)
#endif

static MUTEX notifyRecordMutex;
static MUTEX asyncCallbackMutex;

/* TCL Interpe variable */
static Tcl_Interp *sInterp = NULL;

/*
 *----------------------------------------------------------------------
 *
 * Pjsiptcl_Init --
 *
 *	The package initialization procedure.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side Effects:
 *   Tcl commands created
 *----------------------------------------------------------------------
 */
 /* Set default config. */
static void default_config(struct app_config *cfg)
{
    char tmp[80];

    pjsua_config_default(&cfg->cfg);
    pj_ansi_sprintf(tmp, "PJSIP-TCL v%s/%s", PJ_VERSION, PJ_OS_NAME);
    pj_strdup2_with_null(app_config.pool, &cfg->cfg.user_agent, tmp);

    pjsua_logging_config_default(&cfg->log_cfg);
    pjsua_media_config_default(&cfg->media_cfg);

    pjsua_transport_config_default(&cfg->udp_cfg);
    cfg->udp_cfg.port = 5060;
    pjsua_transport_config_default(&cfg->rtp_cfg);
    cfg->rtp_cfg.port = 4000;
	
    cfg->duration = NO_LIMIT;
	
	cfg->mic_level = cfg->speaker_level = 1.0;

	/* For debug purpose */
#if defined(DEBUG)
	cfg->log_cfg.level = DEBUG_LEVEL;
	pj_log_set_level( DEBUG_LEVEL );
    cfg->log_cfg.console_level = DEBUG_LEVEL;
	cfg->log_cfg.log_filename = pj_str( LOG_FILE );
#endif
}

static int load_acc_data(struct app_config *cfg, 
						 char *registrar,
						 char *id,
						 char *realm,
						 char *username,
						 char *password, 
						 char *stun1, 
						 char *stun2, 
						 unsigned int maxcalls)
{
	/* outbound proxy */
	if (pjsua_verify_sip_url(registrar) != 0) {
		PJ_LOG(1,(THIS_FILE, 
			  "Error load_acc_data: invalid SIP URL '%s' "
			  "in registrar argument", registrar));
		return -1;
	}

	/* Proxy and reg_uri: equal outboundproxy */
//	cfg->account_cfg.proxy_cnt=1;
//	cfg->account_cfg.proxy[0] = pj_str(registrar);

	cfg->account_cfg.reg_uri = pj_str(registrar);
	cfg->account_cfg.reg_timeout = 300;
	cfg->account_cfg.publish_enabled = PJ_FALSE;

	/* STUN server 1 */
//	cfg->udp_cfg.stun_config.stun_srv1 = pj_str(stun1);
//	cfg->udp_cfg.stun_config.stun_port1 = 3478;
//	cfg->udp_cfg.use_stun = PJ_TRUE;

    /* Copy udp_cfg STUN config to rtp_cfg */
//    cfg->rtp_cfg.use_stun = cfg->udp_cfg.use_stun;
//    cfg->rtp_cfg.stun_config = cfg->udp_cfg.stun_config;
	
	/* STUN server 2 */
//	cfg->udp_cfg.stun_config.stun_srv2 = pj_str(stun2);
//	cfg->udp_cfg.stun_config.stun_port2 = 3478;

	cfg->cfg.max_calls = maxcalls;
	if (cfg->cfg.max_calls < 1 || cfg->cfg.max_calls > MAX_CALLS) {
		PJ_LOG(1,(THIS_FILE,"Error load_acc_data: maximum call setting exceeds "
				    "compile time limit (MAX_CALLS=%d)",
			  MAX_CALLS));
		return -2;
	}
	
	/* ----- SIP URI -------- */
	if ( pjsua_verify_sip_url(id) != PJ_SUCCESS) {
	    PJ_LOG(1,(THIS_FILE, "Error load_acc_data: Invalid SIP URI %s", id));
	    return -3;
	}

	cfg->account_cfg.id = pj_str(id);
	
	/* Default authentication user */
	cfg->account_cfg.cred_count = 1;
	cfg->account_cfg.cred_info[0].username = pj_str(username);
	cfg->account_cfg.cred_info[0].scheme = pj_str("digest");
	
	/* Realm equal to outbound proxy */
	cfg->account_cfg.cred_info[0].realm = pj_str(realm);
		
	/* authentication password */
	cfg->account_cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
	cfg->account_cfg.cred_info[0].data = pj_str(password);

	/* Adds the account as default */
	if ( pjsua_acc_add( &cfg->account_cfg, PJ_TRUE, &current_acc) != PJ_SUCCESS ) {
	    PJ_LOG(1,(THIS_FILE, "Error load_acc_data:Not Account added") );
	    return -4;
	}
		
	return 0;
}


DLLEXPORT int Pjsiptcl_Init(Tcl_Interp *interp)		/* Tcl interpreter. */
{
    typedef struct { 
        char                *cmdname;
        Tcl_ObjCmdProc      *proc;
        Tcl_CmdDeleteProc   *delproc;
    } CmdProcStruct;
	
	CmdProcStruct cmdList[] = {
		{"pjsip::answer", AnswerObjCmd, NULL},
		{"pjsip::dial", DialObjCmd, NULL},
		{"pjsip::devices", DevicesObjCmd, NULL},
		{"pjsip::setdevices", SetDevicesObjCmd, NULL},
		{"pjsip::hangup", HangUpObjCmd, NULL},
        {"pjsip::hold", HoldObjCmd, NULL},
		{"pjsip::level", LevelObjCmd, NULL},
		{"pjsip::notify", NotifyObjCmd, NULL},
		{"pjsip::register", RegisterObjCmd, NULL},
		{"pjsip::reject", RejectObjCmd, NULL},
		{"pjsip::sendtext", SendTextObjCmd, NULL},
		{"pjsip::sendtone", SendToneObjCmd, NULL},
		{"pjsip::state", StateObjCmd, NULL},
		{"pjsip::startring", StartRingObjCmd, NULL},
		{"pjsip::stopring", StopRingObjCmd, NULL},
        {"pjsip::unhold", UnholdObjCmd, NULL},
		{"pjsip::unregister", UnregisterObjCmd, NULL},
		{"pjsip::conflist", ConfListObjCmd, NULL},
		{"pjsip::conflink", ConfLinkObjCmd, NULL},
		{"pjsip::confunlink", ConfUnlinkObjCmd, NULL},
		{NULL, NULL, NULL}
	};

    if (sInterp) {
		Tcl_SetObjResult( interp,  
			    Tcl_NewStringObj( "Error Pjsiptcl_Init: Only one interpreter allowed :-(", -1 ));
		return TCL_ERROR;
    }
    sInterp = interp;
    if (Tcl_InitStubs( interp, "8.1", 0 ) == NULL) {
        return TCL_ERROR;
    }
	
	pjsua_transport_id transport_id = -1;
	unsigned i;
	pj_status_t status;
	
	status = pjsua_create();
	if ( status != PJ_SUCCESS ) {
		Tcl_SetObjResult( interp,  
			    Tcl_NewStringObj( "Error Pjsiptcl_Init: Failed pjsua_create", -1 ));
		return TCL_ERROR;
	}
	
	app_config.pool = pjsua_pool_create("pjsiptcl", 4000, 4000);
	default_config( &app_config );

	//-------- Initialice CallBacks --------
    /* Initialize application callbacks */
    app_config.cfg.cb.on_call_state = &EventCallState;
    app_config.cfg.cb.on_call_media_state = &EventMediaState;
    app_config.cfg.cb.on_incoming_call = &EventIncomingCallState;
    app_config.cfg.cb.on_reg_state = &EventRegistration;
    app_config.cfg.cb.on_pager = &EventText;
//    app_config.cfg.cb.on_call_transfer_status = &on_call_transfer_status;
//    app_config.cfg.cb.on_call_replaced = &on_call_replaced;

    /* Initialize pjsua */
    status = pjsua_init(&app_config.cfg, &app_config.log_cfg, &app_config.media_cfg);
    if (status != PJ_SUCCESS) {
	    pjsua_destroy();
		Tcl_SetObjResult( interp,  
			    Tcl_NewStringObj( "Error Pjsiptcl_Init: Failed pjsua_init", -1 ));
		return TCL_ERROR;	
	}

MUTEXINIT(&notifyRecordMutex);
MUTEXINIT(&asyncCallbackMutex);

/* Set codec Order: speex, g711, gsm */
/*	pjsua_codec_set_priority("speex/16000", (pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+0+9));
	pjsua_codec_set_priority("speex/8000", (pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+1+9));
	pjsua_codec_set_priority("g711", (pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+2+9));
	pjsua_codec_set_priority("gsm", (pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+3+9));
	pjsua_codec_set_priority("L16", (pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+5+9));
	pjsua_codec_set_priority("ilbc", (pj_uint8_t)(PJMEDIA_CODEC_PRIO_NORMAL+4+9));
*/				 
    /* Initialize calls data */
/*
    for (i = 0; i < PJ_ARRAY_SIZE(app_config.call_data); ++i) {
		app_config.call_data[i].timer.id = PJSUA_INVALID_ID;
		app_config.call_data[i].timer.cb = &call_timeout_callback;
    }
*/	

    /* Add UDP transport. */
	status = pjsua_transport_create(PJSIP_TRANSPORT_UDP,
					&app_config.udp_cfg, 
					&transport_id);
	if (status != PJ_SUCCESS) {
	    pjsua_destroy();
		Tcl_SetObjResult( interp,  
			    Tcl_NewStringObj( "Error Pjsiptcl_Init: No transport UDP", -1 ));
		return TCL_ERROR;	
	}	

    if (transport_id == -1) {
		pjsua_destroy();
		PJ_LOG(3,(THIS_FILE, "Error Pjsiptcl_Init: no transport is configured"));
		status = -1;
		Tcl_SetObjResult( interp,  
			    Tcl_NewStringObj( "Error Pjsiptcl_Init: No transport Configured", -1 ));
		return TCL_ERROR;
    }
#if DISABLED_FOR_TICKET_1185
    /* Add RTP transports */
    status = pjsua_media_transports_create(&app_config.rtp_cfg);
    if (status != PJ_SUCCESS)  {
			pjsua_destroy();
			PJ_LOG(3,(THIS_FILE, "Error Pjsiptcl_Init: no Transport added"));
			Tcl_SetObjResult( interp,  
			    Tcl_NewStringObj( "Error Pjsiptcl_Init: No Transport added", -1 ));
			return TCL_ERROR;
	}
#endif
    status = pjsua_start();
    if (status != PJ_SUCCESS) {
		pjsua_destroy();
		return status;
    }
	
	
/*	/* Ring Tone Init 
	app_ring_tone.pool = pjsua_pool_create("tone_gen", 4000, 4000);
	if (pjmedia_tonegen_create(app_ring_tone.pool, 8000, 1, 64 / 10, 16, 0, &app_ring_tone.current_tone) == PJ_SUCCESS) {
		pjsua_conf_add_port(app_ring_tone.pool, app_ring_tone.current_tone, &app_ring_tone.port);
	}
*/	

	/* Sets default Signals Level and Input/Output Devices*/
	pjsua_conf_adjust_tx_level( 0, app_config.mic_level);
	pjsua_conf_adjust_rx_level( 0, app_config.speaker_level);

	app_config.input_dev = app_config.output_dev = 0;


    Tcl_CreateExitHandler( ExitHandler, (ClientData) NULL );

    i = 0 ;
    while(cmdList[i].cmdname) {
        Tcl_CreateObjCommand( interp, cmdList[i].cmdname, cmdList[i].proc,
                (ClientData) NULL, cmdList[i].delproc);
        i++ ;
    }

    sMainThreadID = Tcl_GetCurrentThread();
#if USE_THREAD_EVENTS_METHOD    
    XThread_RegisterThread(interp);
#else
    sTimerToken = Tcl_CreateTimerHandler(kTimerPollEventsMillis, PollEvents, NULL); 
#endif

    return Tcl_PkgProvide( interp, "pjsiptcl", "0.1" );
}

/*
 *----------------------------------------------------------------------
 *
 * PJSIP_SafeInit --
 *
 *	The package initialization procedure for safe interpreters.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side Effects:
 *   Tcl commands created
 *----------------------------------------------------------------------
 */

DLLEXPORT int Pjsiptcl_SafeInit(Tcl_Interp *interp )
{
	return Pjsiptcl_Init( interp );
}

static void PollEvents(ClientData clientData)
{
     MUTEXLOCK(&asyncCallbackMutex);
		if (strlen(asyncCallbackCache) > 0) {
			Tcl_EvalEx(sInterp, asyncCallbackCache, -1, TCL_EVAL_GLOBAL);
			asyncCallbackCache[0] = '\0';
		}
		sTimerToken = Tcl_CreateTimerHandler(kTimerPollEventsMillis, PollEvents, NULL);
     MUTEXUNLOCK(&asyncCallbackMutex);
}

static void ExitHandler(ClientData clientData)
{
    if (sTimerToken != NULL) {
        Tcl_DeleteTimerHandler(sTimerToken);
    }

    if (app_config.pool) {
		pj_pool_release(app_config.pool);
		app_config.pool = NULL;
    }
	
	pjsua_call_hangup_all();
	pjsua_destroy();

    MUTEXDESTROY(&notifyRecordMutex);
	MUTEXDESTROY(&asyncCallbackMutex);
}

/*--------------------------------------------------------------------------------
  ---------------------------- PJSIP operations wrapper --------------------------
  --------------------------------------------------------------------------------*/
static int AnswerObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{	
    int result = TCL_OK;
    Tcl_Obj *listObj = NULL;

    pjsua_call_info call_info;

	if (current_call >= 0) {
		pjsua_call_get_info(current_call, &call_info);
	} else {
		/* Make compiler happy */
		call_info.role = PJSIP_ROLE_UAC;
		call_info.state = PJSIP_INV_STATE_DISCONNECTED;
	}
	
	if (current_call == -1 || 
		call_info.role != PJSIP_ROLE_UAS ||
		call_info.state >= PJSIP_INV_STATE_CONNECTING)
	{
			PJ_LOG(3,(THIS_FILE, "AnswerObjCmd: No current call"));

			listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( pjsua_acc_get_default() ) );
			Tcl_SetObjResult(interp, Tcl_NewStringObj("AnswerObjCmd: No current_call", -1));
			result = TCL_ERROR;
	} else {
		/* Sends 200 (OK) SIP response to the INVITE request */
		pjsua_call_answer(current_call, 200, NULL, NULL);
		char buf[32];
		sprintf(buf, "AnswerObjCmd: %d", current_call);
		Tcl_SetObjResult(interp, Tcl_NewStringObj(buf, -1));
	}

    return result;
}

static int DialObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
	char *uri = NULL;
	pj_str_t tmp;
		
	if (objc == 2 ) {
	    uri = Tcl_GetStringFromObj(objv[1], NULL);
	} else {
		Tcl_WrongNumArgs( interp, 1, objv, "uri" );
		result = TCL_ERROR;
    }

	if (result == TCL_OK) {
		tmp = pj_str(uri);
	    pjsua_call_make_call( pjsua_acc_get_default(), &tmp, 0, NULL, NULL, NULL);
	} 
    return result;	
}

static int SetDevicesObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	int	input = 0;
	int output = 0;
    int index;
    int value;
	pj_status_t status;

    if (objc == 3) {
        if (Tcl_GetIndexFromObj( interp, objv[1], devicesCmd, "command", TCL_EXACT, &index )
                != TCL_OK ) {
            return TCL_ERROR;
        }
        if (Tcl_GetIntFromObj(interp, objv[2], &value) != TCL_OK) {
            return TCL_ERROR;
        } 

		//Get Current I/O Dev
		input = app_config.input_dev;
		output = app_config.output_dev;

        switch (index) {
            case kPjsipInput: input = value; break;
            case kPjsipOutput: output = value; break;
        }
		
		// Change Current I/O Dev
        status = pjsua_set_snd_dev( input, output);
		if ( status == PJ_SUCCESS ) {
			app_config.input_dev = input;
			app_config.output_dev = output;
		} else {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("SetDevicesObjCmd: Wrong device", -1));
			return TCL_ERROR;
		}
    } else {
		Tcl_WrongNumArgs( interp, 1, objv, "type deviceid" );
		return TCL_ERROR;
    }
    return TCL_OK;
}

static int DevicesObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int index;
	pjmedia_snd_dev_info sdi[10];
  	pjmedia_snd_dev_info *dev_info;
    int ndevs = PJ_ARRAY_SIZE(sdi);		/* audio dedvice count */
    int input, output;					/* audio device id's */
    int current = 0, i;
    int len, count;
	char *str;

	Tcl_Obj *listObj, *subListObj;

    if (objc != 2 && objc != 3) {
        Tcl_WrongNumArgs( interp, 1, objv, "type ?-current?" );
	    return TCL_ERROR;
    }
	if (Tcl_GetIndexFromObj( interp, objv[1], devicesCmd, "command", TCL_EXACT, &index )
	        != TCL_OK ) {
	    return TCL_ERROR;
	}
    if (objc == 3) {
		str = Tcl_GetStringFromObj(objv[2], &len);
        if (strncmp(str, "-current", len)) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("type ?-current?", -1));
            return TCL_ERROR;
        }
    }

	//Get Current I/O Dev
	input = app_config.input_dev;
	output = app_config.output_dev;
	
    listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
    if (objc == 3) {
        switch (index) {
            case kPjsipInput: current = input; break;
            case kPjsipOutput: current = output; break;
        }
		
		dev_info = pjmedia_snd_get_dev_info(current);
		if ( dev_info ) {
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewStringObj(dev_info->name, -1) );				
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj(current) );
		} else {
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewStringObj("PJSIPTCL Error: getdevices current", -1) );				
		}
		Tcl_SetObjResult( interp, listObj );
    } else {
		if (pjsua_enum_snd_devs(sdi, &ndevs) == PJ_SUCCESS) {
			for (i = 0; i < ndevs; ++i) {
				/* Get the devices for input or output depends of the channel count */
		        switch (index) {
					case kPjsipInput: count = sdi[i].input_count; break;
					case kPjsipOutput: count = sdi[i].output_count; break;
				}
				if ( count > 0 ) {
					subListObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
					Tcl_ListObjAppendElement( interp, subListObj, Tcl_NewStringObj(sdi[i].name, -1) );				
					Tcl_ListObjAppendElement( interp, subListObj, Tcl_NewIntObj(i) );				
					Tcl_ListObjAppendElement( interp, listObj, subListObj );
				}
			}
		} else {
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewStringObj("PJSIPTCL Error: getdevices list", -1) );				
		}
        Tcl_SetObjResult( interp, listObj );
    }
    return TCL_OK;
}

static int HangUpObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
    Tcl_Obj *listObj = NULL;

	if (current_call >= 0) {
		/* Hangup current calls */
		pjsua_call_hangup(current_call, 0, NULL, NULL);
	} else {
		PJ_LOG(3,(THIS_FILE, "HangUpObjCmd: No current_call"));

		listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
		Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( pjsua_acc_get_default() ) );
		Tcl_SetObjResult(interp, Tcl_NewStringObj("HangUpObjCmd: No current_call", -1));
        result = TCL_ERROR;
    }
    return result;
}

static int RejectObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
    Tcl_Obj *listObj = NULL;
	
	if (current_call >= 0) {
		/* Hangup current calls */
		pjsua_call_hangup(current_call, 0, NULL, NULL);
	} else {
		PJ_LOG(3,(THIS_FILE, "RejectObjCmd: No current_call"));

		listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
		Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( pjsua_acc_get_default() ) );
		Tcl_SetObjResult(interp, Tcl_NewStringObj("RejectObjCmd: No current_call", -1));
        result = TCL_ERROR;
	}
    return result;
}


static int HoldObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
    Tcl_Obj *listObj = NULL;
	
	if (current_call != -1) {
		pjsua_call_set_hold(current_call, NULL);
	} else {
		PJ_LOG(3,(THIS_FILE, "HoldObjCmd: No current_call"));
		listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
		Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( pjsua_acc_get_default() ) );
		Tcl_SetObjResult(interp, Tcl_NewStringObj("HoldObjCmd: No current_call", -1));
        result = TCL_ERROR;
	}
    return result;
}

static int UnholdObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
    Tcl_Obj *listObj = NULL;
	
	if (current_call != -1) {		
		pjsua_call_reinvite(current_call, PJ_TRUE, NULL);
	} else {
		PJ_LOG(3,(THIS_FILE, "UnholdObjCmd: No current_call"));
		listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
		Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( pjsua_acc_get_default() ) );
		Tcl_SetObjResult(interp, Tcl_NewStringObj("UnholdObjCmd: No current_call", -1));
        result = TCL_ERROR;
	}
    return result;
}

static int LevelObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int index;
	double level;

    CONST char *levelCmd[] = {
        "input", 
        "output", 
        (char *) NULL
    };
    enum {
        kPjsipLevelInput                = 0L, 
        kPjsipLevelOutput
    };

    if (objc != 2 && objc != 3) {
        Tcl_WrongNumArgs( interp, 1, objv, "type ?value?" );
	    return TCL_ERROR;
    }
	if (Tcl_GetIndexFromObj( interp, objv[1], levelCmd, "command", TCL_EXACT, &index )
	        != TCL_OK ) {
	    return TCL_ERROR;
	}
		
    if (index == kPjsipLevelInput) {
        if (objc == 3) {
            if (TCL_OK != Tcl_GetDoubleFromObj(interp, objv[2], &level)) {
                return TCL_ERROR;
            }
			if (pjsua_conf_adjust_tx_level(0, (float)level) != PJ_SUCCESS) {
				PJ_LOG(3,(THIS_FILE, "Error Level: set tx signal level"));
				return TCL_ERROR;
			}
			app_config.mic_level = (float)level;
        }
        Tcl_SetObjResult( interp, Tcl_NewDoubleObj((double)app_config.mic_level) );
    } else if (index == kPjsipLevelOutput) {
        if (objc == 3) {
            if (TCL_OK != Tcl_GetDoubleFromObj(interp, objv[2], &level)) {
                return TCL_ERROR;
            }
			if (pjsua_conf_adjust_rx_level(0, (float)level) != PJ_SUCCESS) {
				PJ_LOG(3,(THIS_FILE, "Error Level: set rx signal level"));
				return TCL_ERROR;
			}
			app_config.speaker_level = (float)level;
        }
        Tcl_SetObjResult( interp, Tcl_NewDoubleObj((double)app_config.speaker_level) );
    }
    return TCL_OK;
}

static int RegisterObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	char *registrar;
	char *id;
	char *realm;
	char *username;
	char *password;
	char *stun1;
						
    int result = TCL_OK;
	int load_acc_result = 0;
    Tcl_Obj *listObj = NULL;

    if (objc == 7) {
        registrar	= Tcl_GetStringFromObj(objv[1], NULL);
		id			= Tcl_GetStringFromObj(objv[2], NULL);
		realm		= Tcl_GetStringFromObj(objv[3], NULL);
        username	= Tcl_GetStringFromObj(objv[4], NULL);
        password	= Tcl_GetStringFromObj(objv[5], NULL);
        stun1		= Tcl_GetStringFromObj(objv[6], NULL);

		load_acc_result = load_acc_data(&app_config, registrar, id, realm, username, password, stun1, stun1, MAX_CALLS);

		switch ( load_acc_result ) {
			case -1:
				Tcl_SetObjResult(interp, Tcl_NewStringObj("Error RegisterObjCmd: Loading Account (Registrar)", -1));
				result = TCL_ERROR;
				break;
			case -2:
				Tcl_SetObjResult(interp, Tcl_NewStringObj("Error RegisterObjCmd: Loading Account (maxCalls)", -1));
				result = TCL_ERROR;
				break;
			case -3:
				Tcl_SetObjResult(interp, Tcl_NewStringObj("Error RegisterObjCmd: Loading Account (SIP ID)", -1));
				result = TCL_ERROR;
				break;
			case -4:
				Tcl_SetObjResult(interp, Tcl_NewStringObj("Error RegisterObjCmd: Loading Account (acc_add)", -1));
				result = TCL_ERROR;
				break;
		}

		load_acc_result = pjsua_acc_set_registration(pjsua_acc_get_default(), PJ_TRUE);
		
		/* Return Current_Account_id */
		listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
		Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( pjsua_acc_get_default() ) );
		Tcl_SetObjResult(interp, listObj);		
    } else {
        Tcl_WrongNumArgs( interp, 1, objv, "registrar id realm username password stun" );
        result = TCL_ERROR;
    }
    return result;
}

static int UnregisterObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{

	pjsua_acc_set_registration(pjsua_acc_get_default(), PJ_FALSE);
    return TCL_OK;

}

static int CallerIDObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;

    if (objc == 3) {
        char *name;
		char *num;
        char *id;
		name = Tcl_GetStringFromObj(objv[1], NULL);
        num = Tcl_GetStringFromObj(objv[2], NULL);
		sprintf(id, "From:\"%s %s\"<%s>", name, num, app_config.account_cfg.id);

		if ( pjsua_verify_sip_url(id) != PJ_SUCCESS) {
			PJ_LOG(3,(THIS_FILE, "Error CallerID: Incorrect SIP URI (%s)", id));
			Tcl_SetObjResult(interp, Tcl_NewStringObj("Error CallerID: Incorrect SIP URI", -1));
			result = TCL_ERROR;
		}
		app_config.account_cfg.id = pj_str(id);
		pjsua_acc_set_registration(pjsua_acc_get_default(), PJ_TRUE);
    } else {
        Tcl_WrongNumArgs( interp, 1, objv, "sid" );
        result = TCL_ERROR;
    }
    return result;
}


static int SendTextObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
    Tcl_Obj *listObj = NULL;
	
    if (objc == 2) {
        char *text;
		pj_str_t tmp;
        /* Encoding ? */
        text = Tcl_GetStringFromObj(objv[1], NULL);

	    /* Send the IM */
	    if (current_call != -1) {
			tmp = pj_str( text );
			pjsua_call_send_im(current_call, NULL, &tmp, NULL, NULL);
		} else {
			PJ_LOG(3,(THIS_FILE, "SendTextObjCmd: No current_call"));
			listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( pjsua_acc_get_default() ) );
			Tcl_SetObjResult(interp, Tcl_NewStringObj("SendTextObjCmd: No current_call", -1));
			result = TCL_ERROR;
		}
    } else {
        Tcl_WrongNumArgs( interp, 1, objv, "text" );
        result = TCL_ERROR;
    }
    return result;
}

static int SendToneObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
	
    if (objc == 2) {
        char *s;
        int len;
		pj_status_t status;
	
        s = Tcl_GetStringFromObj(objv[1], &len);
        if (len != 1) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("Error SendToneObjCmd: Param must be a ring tone", -1));
            result = TCL_ERROR;
        }
        if (!strchr(dtmf_tones, s[0])) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("Error SendToneObjCmd: Param must be a ring tone", -1));
            result = TCL_ERROR;
        }
		
		pj_str_t digits;
		digits = pj_str(dtmf_tones);
		status = pjsua_call_dial_dtmf(current_call, &digits);
    } else {
        Tcl_WrongNumArgs( interp, 1, objv, "tone" );
        result = TCL_ERROR;
    }
    return result;
}


static int StartRingObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
	
	pj_status_t status;			
	pjmedia_tone_desc tones[PJMEDIA_TONEGEN_MAX_DIGITS];
	int mFreq1 = 440;
	int mFreq2 = 480;
	int mOnMs = 2000;
	int mOffMs = 4000;
	int mVolume = 16383;
	int i;
	
	if ( !app_ring_tone.current_tone ) return TCL_ERROR;
	
	
	pjmedia_tonegen_stop(app_ring_tone.current_tone);

	// We can only queue up 32 iterations at a time.
	for (i=0; i<PJMEDIA_TONEGEN_MAX_DIGITS; i++) {
		tones[i].freq1 = mFreq1;
		tones[i].freq2 = mFreq2;
		tones[i].on_msec = mOnMs;
		tones[i].off_msec = mOffMs;
		tones[i].volume = mVolume;
	}
	status = pjmedia_tonegen_play(app_ring_tone.current_tone, PJMEDIA_TONEGEN_MAX_DIGITS, tones, 0);

	pjsua_conf_connect(app_ring_tone.port, 0);
	
    return result;
}

static int StopRingObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
    int result = TCL_OK;
	
	pjsua_conf_disconnect(app_ring_tone.port, 0);

    return result;
}

	
static int StateObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
{
	int result = TCL_OK;
	int call_count;
	
    if (objc == 1) {
#if defined(DEBUG)
		pj_dump_config();
		pjsip_endpt_dump(pjsua_get_pjsip_endpt(), PJ_TRUE);
		pjmedia_endpt_dump( pjsua_get_pjmedia_endpt() );
		pjsip_tsx_layer_dump( PJ_TRUE );
		pjsip_ua_dump( PJ_TRUE );
#endif
		call_count = pjsua_call_get_count();
		
		if ( call_count > 0 ) {
			char buf[1024];
			if ( pjsua_call_is_active( current_call ) ) {
				pjsua_call_dump(current_call, PJ_TRUE, buf, sizeof(buf), "  ");
				PJ_LOG(3,(THIS_FILE, "CallState: \n%s", buf));
				Tcl_SetObjResult(interp, Tcl_NewStringObj(buf, -1));
			} else {
				PJ_LOG(3,(THIS_FILE, "CallState: No active session"));
				Tcl_SetObjResult(interp, Tcl_NewStringObj("CallState: No active session", -1));
				result = TCL_ERROR;
			}
		} else {
			PJ_LOG(3,(THIS_FILE, "CallState: No calls"));
            Tcl_SetObjResult(interp, Tcl_NewStringObj("CallState: No calls", -1));
			result = TCL_ERROR;
		}
	} else {
        Tcl_WrongNumArgs( interp, 1, objv, NULL );
        result = TCL_ERROR;
    }
	
	return result;
}

 /*
  * This is always called from the Tcl main thread.
  */
 
 static int NotifyObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[])
 {
     int index;
     int len;
	 int result = TCL_OK;
	 
     if (objc != 2 && objc != 3) {
		Tcl_WrongNumArgs( interp, 1, objv, "eventType ?tclProc?" );
 	    result = TCL_ERROR;
     }
 	if (Tcl_GetIndexFromObj( interp, objv[1], notifyCmd, "command", TCL_EXACT, &index ) != TCL_OK ) {
 	    result = TCL_ERROR;
 	}
 
     MUTEXLOCK(&notifyRecordMutex);
		if (objc == 3) {
			if (sNotifyRecord[index]) {
				Tcl_DecrRefCount(sNotifyRecord[index]);
				sNotifyRecord[index] = NULL;
			}
			Tcl_GetStringFromObj(objv[2], &len);
			if (len > 0) {
				/*
				* Most command procedures do not have to be concerned about reference counting
				* since they use an object's value immediately and don't retain a pointer to
				* the object after they return. However, if they do retain a pointer to an
				* object in a data structure, they must be careful to increment its reference
				* count since the retained pointer is a new reference.
				*/
				//sNotifyRecord[index] = Tcl_DuplicateObj(objv[2]);
				sNotifyRecord[index] = objv[2];
				Tcl_IncrRefCount(sNotifyRecord[index]);
			}
		}
		if (sNotifyRecord[index]) {
			Tcl_SetObjResult(interp, sNotifyRecord[index]);
		}
     MUTEXUNLOCK(&notifyRecordMutex);
     return result;
}

/*-------------------------------- CallBack Handlers -----------------------------------------*/
/* Callback from timer when the maximum call duration has been
 * exceeded.
 */

static void call_timeout_callback(pj_timer_heap_t *timer_heap,
				  struct pj_timer_entry *entry)
{
    pjsua_call_id call_id = entry->id;
    pjsua_msg_data msg_data;
    pjsip_generic_string_hdr warn;
    pj_str_t hname = pj_str("TimeoutEvent: Warning");
    pj_str_t hvalue = pj_str("399 pjsua \"Call duration exceeded\"");

    PJ_UNUSED_ARG(timer_heap);

    if (call_id == PJSUA_INVALID_ID) {
		PJ_LOG(1,(THIS_FILE, "TimeoutEvent: Invalid call ID in timer callback"));
		return;
    }
    
    // Add warning header
    pjsua_msg_data_init(&msg_data);
    pjsip_generic_string_hdr_init2(&warn, &hname, &hvalue);
    pj_list_push_back(&msg_data.hdr_list, &warn);

    // Call duration has been exceeded; disconnect the call
    PJ_LOG(3,(THIS_FILE, "TimeoutEvent: Duration (%d seconds) has been exceeded "
			 "for call %d, disconnecting the call",
			 app_config.duration, call_id));
    entry->id = PJSUA_INVALID_ID;
//    pjsua_call_hangup(call_id, 200, NULL, &msg_data);
}


static void EventText(pjsua_call_id call_id, const pj_str_t *from, const pj_str_t *to, const pj_str_t *contact, const pj_str_t *mime_type, const pj_str_t *text)
{		  		  
	MUTEXLOCK(&notifyRecordMutex);	
		PJ_LOG(4,(THIS_FILE,"Text Event"));
			
		if (sNotifyRecord[kNotifyCmdText]) {
			char *cmd;
			int len;
			Tcl_DString ds, ds2;

			/* Get Call Info */
			/* Note: call index may be -1 */
			PJ_UNUSED_ARG(call_id);
			PJ_UNUSED_ARG(to);
			PJ_UNUSED_ARG(contact);
			PJ_UNUSED_ARG(mime_type);
			
			Tcl_DStringInit(&ds);
			Tcl_DStringInit(&ds2);
			cmd = Tcl_GetStringFromObj(sNotifyRecord[kNotifyCmdText], &len);
			Tcl_DStringAppend(&ds, cmd, len);
			
			Tcl_DStringAppendElement(&ds, from->ptr);
			Tcl_DStringAppendElement(&ds, text->ptr);
			
			XThread_EvalInThread(sMainThreadID, Tcl_DStringValue(&ds), 0);
			Tcl_DStringFree(&ds);
			Tcl_DStringFree(&ds2);
		}
	MUTEXUNLOCK(&notifyRecordMutex);
}

static void EventCallState(pjsua_call_id call_id, pjsip_event *e)
{
    MUTEXLOCK(&notifyRecordMutex);
		if (sNotifyRecord[kNotifyCmdState]) {
			char *cmd;
			char buf[32];
			int len;
			Tcl_DString ds, ds2;

			/* Get Call Info */
			pjsua_call_info call;
			PJ_UNUSED_ARG(e);
			pjsua_call_get_info(call_id, &call);

			if (call.state == PJSIP_INV_STATE_DISCONNECTED) {
				//Cancel duration timer, if any 
				if (app_config.call_data[call_id].timer.id != PJSUA_INVALID_ID) {
					struct call_data *cd = &app_config.call_data[call_id];
					pjsip_endpoint *endpt = pjsua_get_pjsip_endpt();
					
					cd->timer.id = PJSUA_INVALID_ID;
					pjsip_endpt_cancel_timer(endpt, &cd->timer);
				}
				
				/* When inactive call then clear the current_call variable */
				current_call = PJSUA_INVALID_ID;
				
				PJ_LOG(3,(THIS_FILE, "Call %d is DISCONNECTED [reason=%d (%s)]", 
						  call_id,
						  call.last_status,
						  call.last_status_text.ptr));
				
				//Dump media state upon disconnected
				if (1) {
					char buf[1024];
					pjsua_call_dump(call_id, PJ_TRUE, buf, sizeof(buf), "  ");
					PJ_LOG(5,(THIS_FILE, 
							  "Call %d disconnected, dumping media stats\n%s", 
							  call_id, buf));
				}
			} else {
				if (call.state == PJSIP_INV_STATE_EARLY) {
					int code;
					pj_str_t reason;
					pjsip_msg *msg;
					
					//This can only occur because of TX or RX message
					//pj_assert(e->type == PJSIP_EVENT_TSX_STATE);
					
					if (e->body.tsx_state.type == PJSIP_EVENT_RX_MSG) {
						msg = e->body.tsx_state.src.rdata->msg_info.msg;
					} else {
						msg = e->body.tsx_state.src.tdata->msg;
					}
					
					code = msg->line.status.code;
					reason = msg->line.status.reason;
				
					PJ_LOG(3,(THIS_FILE, "Call %d state changed to %s (%d %.*s)", 
							  call_id, call.state_text.ptr,
							  code, (int)reason.slen, reason.ptr));
				} else {
					PJ_LOG(3,(THIS_FILE, "Call %d state changed to %s", 
							  call_id,
							  call.state_text.ptr));
				}

				if (current_call != PJSUA_INVALID_ID) {
					char buf[1024];
					pjsua_call_dump(current_call, PJ_TRUE, buf, sizeof(buf), "  ");
					PJ_LOG(3,(THIS_FILE, "CallState dump: \n%s", buf));
				} else {
					PJ_LOG(3,(THIS_FILE, "CallState dump: No current call (%d)", call_id));
				}
				
				if (current_call==PJSUA_INVALID_ID)
					current_call = call_id;
			}
			

			Tcl_DStringInit(&ds);
			Tcl_DStringInit(&ds2);
			cmd = Tcl_GetStringFromObj(sNotifyRecord[kNotifyCmdState], &len);
			Tcl_DStringAppend(&ds, cmd, len);
			sprintf(buf, "%d", call.id);
			Tcl_DStringAppendElement(&ds, buf);
			Tcl_DStringAppendElement(&ds, call.call_id.ptr);
			Tcl_DStringAppendElement(&ds, call.state_text.ptr);
			Tcl_DStringAppendElement(&ds, call.last_status_text.ptr);
			XThread_EvalInThread(sMainThreadID, Tcl_DStringValue(&ds), 0);
			Tcl_DStringFree(&ds);
			Tcl_DStringFree(&ds2);
		}
	MUTEXUNLOCK(&notifyRecordMutex);	
}


static void EventIncomingCallState(pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data *rdata)
{
    MUTEXLOCK(&notifyRecordMutex);
		PJ_LOG(4,(THIS_FILE,"Incoming Event"));
		
		if (sNotifyRecord[kNotifyCmdIncoming]) {
			char *cmd;
			char buf[32];
			int len;
			Tcl_DString ds, ds2;

			pjsua_call_info call;

			PJ_UNUSED_ARG(acc_id);
			PJ_UNUSED_ARG(rdata);
	
			/* Get Call Info */
			pjsua_call_get_info(call_id, &call);

			if (current_call==PJSUA_INVALID_ID)
				current_call = call_id;
					
			PJ_LOG(3,(THIS_FILE,
				"Incoming call (%d) for account %d!\n"
				"From: %s\n"
				"To: %s\n",
				call_id,
				acc_id,
				call.remote_info.ptr,
				call.local_info.ptr));
		  			
			Tcl_DStringInit(&ds);
			Tcl_DStringInit(&ds2);
			cmd = Tcl_GetStringFromObj(sNotifyRecord[kNotifyCmdIncoming], &len);
			Tcl_DStringAppend(&ds, cmd, len);
			
			sprintf(buf, "%d", call_id);
			Tcl_DStringAppendElement(&ds, buf);
			sprintf(buf, "%d", acc_id);
			Tcl_DStringAppendElement(&ds, buf);
			Tcl_DStringAppendElement(&ds, call.remote_info.ptr);
			Tcl_DStringAppendElement(&ds, call.local_info.ptr);
			
			XThread_EvalInThread(sMainThreadID, Tcl_DStringValue(&ds), 0);
			Tcl_DStringFree(&ds);
			Tcl_DStringFree(&ds2);
		}
	MUTEXUNLOCK(&notifyRecordMutex);	
}

static void EventRegistration(pjsua_acc_id acc_id)
{
	MUTEXLOCK(&notifyRecordMutex);		
		if (sNotifyRecord[kNotifyCmdRegistration]) {
			char *cmd;
			char buf[32];
			int len;
			Tcl_DString ds, ds2;
			
			Tcl_DStringInit(&ds);
			Tcl_DStringInit(&ds2);
			cmd = Tcl_GetStringFromObj(sNotifyRecord[kNotifyCmdRegistration], &len);	

			Tcl_DStringAppend(&ds, cmd, len);

			sprintf(buf, "%d", acc_id);
			Tcl_DStringAppendElement(&ds, buf);

			XThread_EvalInThread(sMainThreadID, Tcl_DStringValue(&ds), 0);
			Tcl_DStringFree(&ds);
			Tcl_DStringFree(&ds2);
		}
	MUTEXUNLOCK(&notifyRecordMutex);
}

/*
 * Callback on media state changed event.
 * The action may connect the call to sound device, to file, or
 * to loop the call.
 */
static void EventMediaState(pjsua_call_id call_id) {
	MUTEXLOCK(&notifyRecordMutex);
		if (sNotifyRecord[kNotifyCmdMedia]) {
			char *cmd;
			char buf[32], media_state_text[32];
			int len;
			Tcl_DString ds, ds2;
			
		    pjsua_call_info call_info;
			pjsua_call_get_info(call_id, &call_info);

			if (call_info.media_status == PJSUA_CALL_MEDIA_ACTIVE) {
				pj_bool_t connect_sound = PJ_TRUE;
				/* Here we can setup auto-answer, wav-stream, loopback sound, etc */ 
	
				/* Otherwise connect to sound device */
				if (connect_sound) {
					pjsua_conf_connect(call_info.conf_slot, 0);
					pjsua_conf_connect(0, call_info.conf_slot);
				}		
				sprintf(media_state_text, "active");
				PJ_LOG(3,(THIS_FILE, "Media for call %d is active", call_id));
			} else if (call_info.media_status == PJSUA_CALL_MEDIA_LOCAL_HOLD) {
				sprintf(media_state_text, "hold_local");
				PJ_LOG(3,(THIS_FILE, "Media for call %d is suspended (hold) by local", call_id));
			} else if (call_info.media_status == PJSUA_CALL_MEDIA_REMOTE_HOLD) {
				sprintf(media_state_text, "hold_remote");
				PJ_LOG(3,(THIS_FILE, "Media for call %d is suspended (hold) by remote", call_id));
			} else {
				sprintf(media_state_text, "inactive");
				PJ_LOG(3,(THIS_FILE, "Media for call %d is inactive", call_id));
			}

			/* Executes TCL Callback */	
			Tcl_DStringInit(&ds);
			Tcl_DStringInit(&ds2);
			cmd = Tcl_GetStringFromObj(sNotifyRecord[kNotifyCmdIncoming], &len);
			Tcl_DStringAppend(&ds, cmd, len);
			
			sprintf(buf, "%d", call_id);
			Tcl_DStringAppendElement(&ds, buf);
			sprintf(buf, "%d", call_info.acc_id);
			Tcl_DStringAppendElement(&ds, buf);
			Tcl_DStringAppendElement(&ds, media_state_text);
			sprintf(buf, "%d", call_info.total_duration.sec);
			Tcl_DStringAppendElement(&ds, buf);
			Tcl_DStringAppendElement(&ds, call_info.remote_info.ptr);
			Tcl_DStringAppendElement(&ds, call_info.local_info.ptr);
		}
	MUTEXUNLOCK(&notifyRecordMutex);		
 }

#if 0
static void EvalScriptAsync(Tcl_Obj *cmdObj)
{
     char *script;
     int len;
 
	PJ_LOG(4,(THIS_FILE,"EvalScriptAsync"));

     script = Tcl_GetStringFromObj(cmdObj, &len);
 
 #if USE_THREAD_EVENTS_METHOD
     XThread_EvalInThread(sMainThreadID, script, 0);
 #else
     MUTEXLOCK(&asyncCallbackMutex);
 
     /* Do not add commands that do not fit. */
     if (strlen(asyncCallbackCache) + len < kNotifyCallbackCacheSize - 2) {
         strcat(asyncCallbackCache, script);
         strcat(asyncCallbackCache, "\n");
     }
     MUTEXUNLOCK(&asyncCallbackMutex);
 #endif
 }
#endif

/* Test Commands */
static int ConfLinkObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    pj_status_t status;
	int srcPort;
	int dstPort;
	
	int result = TCL_OK;

    if (objc == 3) {
		Tcl_GetIntFromObj(interp, objv[1], &srcPort);
		Tcl_GetIntFromObj(interp, objv[2], &dstPort);
		
		status = pjsua_conf_connect(srcPort, dstPort);
	}
    return result;
}

static int ConfUnlinkObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    pj_status_t status;
	int srcPort;
	int dstPort;
	
	int result = TCL_OK;

    if (objc == 3) {
		Tcl_GetIntFromObj(interp, objv[1], &srcPort);
		Tcl_GetIntFromObj(interp, objv[2], &dstPort);

		status = pjsua_conf_disconnect(srcPort, dstPort);
	}
    return result;
}

static int ConfListObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
    unsigned i, count;
    pjsua_conf_port_id id[MAX_CALLS];
	
	int result = TCL_OK;
    Tcl_Obj *listObj = NULL;

	count = PJ_ARRAY_SIZE(id);
	pjsua_enum_conf_ports(id, &count);

	/* Return Current Conference Ports */
	listObj = Tcl_NewListObj( 0, (Tcl_Obj **) NULL );
	
	if ( count ) {
		for (i = 0; i < count; ++i) {
			char txlist[MAX_CALLS*4+10];
			unsigned j;
			pjsua_conf_port_info info;

			pjsua_conf_get_port_info(id[i], &info);

			txlist[0] = '\0';
			for (j=0; j<info.listener_cnt; ++j) {
				char s[10];
				pj_ansi_sprintf(s, "#%d ", info.listeners[j]);
				pj_ansi_strcat(txlist, s);
			}

			char buf[1024];
			pj_ansi_sprintf(buf, "Port #%02d[%2dKHz/%dms] %20.*s  transmitting to: %s\n", 
				info.slot_id, 
				info.clock_rate/1000,
				info.samples_per_frame * 1000 / info.clock_rate,
				(int)info.name.slen, 
				info.name.ptr,
				txlist);
			PJ_LOG(3,(THIS_FILE, "Conf List: \n%s", buf));
				
				
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewStringObj( "-- Port:", -1) );
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewIntObj( info.slot_id ) );
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewStringObj( info.name.ptr, -1) );
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewStringObj( txlist, -1) );
		}
	} else {
			Tcl_ListObjAppendElement( interp, listObj, Tcl_NewStringObj( "No conferences available", -1) );
	}
	Tcl_SetObjResult(interp, listObj);
	
    return result;
}

/* End Test Commands */