
#include "tls.h"

STR_CIPHER_SUITE	strCipherSuites[]=
{
	{
		"TLS_RSA_WITH_RC4_128_MD5",
		{
			0x00,
			CST_RC4_128_MD5,	
		},
	},
	{
		"TLS_RSA_WITH_RC4_128_SHA",
		{
			0x00,
			CST_RC4_128_SHA,	
		},
	},
	{
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		{
			0x00,
			CST_AES128_CBC_SHA,	
		},
	},
	{
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		{
			0x00,
			CST_AES256_CBC_SHA,	
		},
	},
};


int ecpTlsSetCipherSuite()
{
}

fsm_event_t	eventsInOffState[] =
{
	{
		TLS_EVENT_APP,
		send_client_hello,	
	},
		
};

static fsm_req_status_t	clientStates[] =
{
	{
		TLS_STATE_OFF,
		sizeof( eventsInOffState)/sizeof(fsm_event_t),
		eventsInOffState,
	},
	{
		TLS_STATE_CLIENT_HELLO,
		sizeof( readRequestEvents)/sizeof(fsm_event_t),
		readRequestEvents,
	},
	{
		TLS_STATE_SERVER_HELLO,
		sizeof( readRequestEvents)/sizeof(fsm_event_t),
		readRequestEvents,
	},
	{
		TLS_STATE_CLIENT_FINISH,
		sizeof( readRequestEvents)/sizeof(fsm_event_t),
		readRequestEvents,
	},
	{
		TLS_STATE_SERVER_FINISH,
		sizeof( readRequestEvents)/sizeof(fsm_event_t),
		readRequestEvents,
	},
	{
		TLS_STATE_APP,
		sizeof( readRequestEvents)/sizeof(fsm_event_t),
		readRequestEvents,
	},
	{
		TLS_STATE_RENEGOTIATE,
		sizeof( readRequestEvents)/sizeof(fsm_event_t),
		readRequestEvents,
	},

};

TLS_FSM		_clientFsm =
{
	sizeof( clientStates)/sizeof(fsm_req_status_t),
	clientStates,
};

static TLS_STATE_T _fsmHandlers(SSL *ssl,  CLIENT_CONN *conn )
{
	int		i, j;
	TLS_STATE_T newState = TLS_STATE_CONTINUE;
	TLS_FSM *fsm = ssl->ctx->fsm;

	for(j=0; j< fsm->size; j++)
	{
		if(fsm->states[j].state == ssl->status)
		{
			for(i =0; i< fsm->states[j].size; i++)
			{
				if(fsm->states[j].events[i].event == conn->event )
				{
					AX_DEBUG("Conn %d : handle event %s in state %s\n", conn->index, _eventName(conn->event) , stateName(fsm->states[j].state) );
					newState = fsm->states[j].events[i].handler( conn);
					break;
				}
			}
		}
	}
	return newState;
}



