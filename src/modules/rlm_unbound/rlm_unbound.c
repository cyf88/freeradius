/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_unbound.c
 * @brief DNS services via libunbound.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Brian S. Julin (bjulin@clarku.edu)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_unbound - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/log.h>
#include <fcntl.h>

#include "io.h"
#include "log.h"

typedef struct {
	struct ub_ctx	*ub;   /* This must come first.  Do not move */

	char const	*name;
	char const	*xlat_a_name;
	char const	*xlat_aaaa_name;
	char const	*xlat_ptr_name;

	uint32_t	timeout;

	char const	*filename;

	unbound_log_t	*u_log;
} rlm_unbound_t;

typedef struct {
	unbound_io_event_base_t	*ev_b;		//!< Unbound event base
	rlm_unbound_t		*inst;		//!< Instance data
	unbound_log_t		*u_log;		//!< Unbound log structure
} rlm_unbound_thread_t;

typedef struct {
	rlm_unbound_t		*inst;		//!< Instance data
	rlm_unbound_thread_t	*t;		//!< Thread structure
} unbound_xlat_thread_inst_t;

typedef struct {
	int			async_id;	//!< Id of async query
	request_t		*request;	//!< Current request being processed
	rlm_unbound_thread_t	*t;		//!< Thread running this request
	int			done;		//!< Indicator that the callback has been called
						///< Negative values indicate errors.
	fr_type_t		return_type;	//!< Data type to parse results into
	bool			has_priority;	//!< Does the returned data start with a priority field
	uint16_t		count;		//!< Number of results to return
	fr_value_box_list_t	list;		//!< Where to put the parsed results
	TALLOC_CTX		*out_ctx;	//!< CTX to allocate parsed results in
} unbound_request_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_unbound_t, filename), .dflt = "${modconfdir}/unbound/default.conf" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, rlm_unbound_t, timeout), .dflt = "3000" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Callback sent to libunbound for xlat functions.  Simply links the
 *	new ub_result via a pointer that has been allocated from the heap.
 *	This pointer has been pre-initialized to a magic value.
 */
static void link_ubres(void *my_arg, int err, struct ub_result *result)
{
	struct ub_result **ubres = (struct ub_result **)my_arg;

	/*
	 *	Note that while result will be NULL on error, we are explicit
	 *	here because that is actually a behavior that is suboptimal
	 *	and only documented in the examples.  It could change.
	 */
	if (err) {
		ERROR("%s", ub_strerror(err));
		*ubres = NULL;
	} else {
		*ubres = result;
	}

}

/**	Callback called by unbound when resolution started with ub_resolve_event() completes
 *
 * @param mydata	the request tracking structure set up before ub_resolve_event() was called
 * @param rcode		should be the rcode from the reply packet, but appears not to be
 * @param packet	wire format reply packet
 * @param packet_len	length of wire format packet
 * @param sec		DNSSEC status code
 * @param why_bogus	String describing DNSSEC issue if sec = 1
 * @param rate_limited	Was the request rate limited due to unbound workload
 */
static void xlat_unbound_callback(void *mydata, int rcode, void *packet, int packet_len, int sec,
				  char* why_bogus, UNUSED int rate_limited)
{
	unbound_request_t	*ur = talloc_get_type_abort(mydata, unbound_request_t);
	request_t		*request = ur->request;
	fr_dbuff_t		dbuff;
	uint16_t		qdcount = 0, ancount = 0, i, rdlength = 0;
	uint8_t			pktrcode = 0, skip = 0;
	ssize_t			used;
	fr_value_box_t		*vb;

	/*
	 *	Bogus responses have the "sec" flag set to 1
	 */
	if (sec == 1) {
		RERROR("%s", why_bogus);
		ur->done = -16;
		goto resume;
	}

	RHEXDUMP4((uint8_t const *)packet, packet_len, "Unbound callback called with packet [length %d]", packet_len);

	fr_dbuff_init(&dbuff, (uint8_t const *)packet, (size_t)packet_len);

	/*	Skip initial header entries */
	fr_dbuff_advance(&dbuff, 3);

	/*
	 *	Extract rcode - it doesn't appear to be passed in as a
	 *	parameter, contrary to the documentation...
	 */
	fr_dbuff_out(&pktrcode, &dbuff);
	rcode = pktrcode & 0x0f;
	if (rcode != 0) {
		ur->done = 0 - rcode;
		REDEBUG("DNS rcode is %d", rcode);
		goto resume;
	}

	fr_dbuff_out(&qdcount, &dbuff);
	if (qdcount > 1) {
		RERROR("DNS results packet with multiple questions");
		ur->done = -32;
		goto resume;
	}

	/*	How many answer records do we have? */
	fr_dbuff_out(&ancount, &dbuff);
	RDEBUG4("Unbound returned %d answers", ancount);

	/*	Skip remaining header entries */
	fr_dbuff_advance(&dbuff, 4);

	/*	Skip the QNAME */
	fr_dbuff_out(&skip, &dbuff);
	while (skip > 0) {
		if (skip > 63) {
			/*
			 *	This is a pointer to somewhere else in the the packet
			 *	Pointers use two octets
			 *	Just move past the pointer to the next label in the question
			 */
			fr_dbuff_advance(&dbuff, 1);
		} else {
			if (fr_dbuff_remaining(&dbuff) < skip) break;
			fr_dbuff_advance(&dbuff, skip);
		}
		fr_dbuff_out(&skip, &dbuff);
	}

	/*	Skip QTYPE and QCLASS */
	fr_dbuff_advance(&dbuff, 4);

	/*	We only want a limited number of replies */
	if (ancount > ur->count) ancount = ur->count;

	fr_value_box_list_init(&ur->list);

	/*	Read the answer RRs */
	for (i = 0; i < ancount; i++) {
		fr_dbuff_out(&skip, &dbuff);
		if (skip > 63) fr_dbuff_advance(&dbuff, 1);

		/*	Skip TYPE, CLASS and TTL */
		fr_dbuff_advance(&dbuff, 8);

		fr_dbuff_out(&rdlength, &dbuff);
		RDEBUG4("RDLENGTH is %d", rdlength);

		vb = fr_value_box_alloc_null(ur->out_ctx);
		switch (ur->return_type) {
		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_OCTETS:
			if (fr_value_box_from_network(ur->out_ctx, vb, ur->return_type, NULL,
						      (uint8_t *)fr_dbuff_current(&dbuff), rdlength, true) < 0) {
			error:
				talloc_free(vb);
				fr_dlist_talloc_free(&ur->list);
				ur->done = -32;
				goto resume;
			}
			fr_dbuff_advance(&dbuff, rdlength);
			break;

		case FR_TYPE_STRING:
			if (ur->has_priority) {
				/*
				 *	This record type has a priority before the label
				 *	add the priority first as a separate box
				 */
				fr_value_box_t	*priority_vb;
				if (rdlength < 3) {
					REDEBUG("%s - Invalid data returned", ur->t->inst->name);
					goto error;
				}
				priority_vb = fr_value_box_alloc_null(ur->out_ctx);
				if (fr_value_box_from_network(ur->out_ctx, priority_vb, FR_TYPE_UINT16, NULL,
							      (uint8_t *)fr_dbuff_current(&dbuff), 2, true) < 0) {
					talloc_free(priority_vb);
					goto error;
				}
				fr_dlist_insert_tail(&ur->list, priority_vb);
				fr_dbuff_advance(&dbuff, 2);
			}

			/*	String types require decoding of dns format labels */
			used = fr_dns_label_to_value_box(ur->out_ctx, vb, (uint8_t const *)packet, packet_len,
							 (uint8_t const *)fr_dbuff_current(&dbuff), true);
			if (used < 0) goto error;
			fr_dbuff_advance(&dbuff, (size_t)used);
			break;

		default:
			RERROR("No meaningful output type set");
			goto error;
		}

		fr_dlist_insert_tail(&ur->list, vb);

	}

	ur->done = 1;

resume:
	unlang_interpret_mark_runnable(ur->request);
}


/*
 *	Convert labels as found in a DNS result to a NULL terminated string.
 *
 *	Result is written to memory pointed to by "out" but no result will
 *	be written unless it and its terminating NULL character fit in "left"
 *	bytes.  Returns the number of bytes written excluding the terminating
 *	NULL, or -1 if nothing was written because it would not fit or due
 *	to a violation in the labels format.
 */
static int rrlabels_tostr(char *out, char *rr, size_t left)
{
	int offset = 0;

	/*
	 * TODO: verify that unbound results (will) always use this label
	 * format, and review the specs on this label format for nuances.
	 */

	if (!left) {
		return -1;
	}
	if (left > 253) {
		left = 253; /* DNS length limit */
	}
	/* As a whole this should be "NULL terminated" by the 0-length label */
	if (strnlen(rr, left) > left - 1) {
		return -1;
	}

	/* It will fit, but does it it look well formed? */
	while (1) {
		size_t count;

		count = *((unsigned char *)(rr + offset));
		if (!count) break;

		offset++;
		if (count > 63 || strlen(rr + offset) < count) {
			return -1;
		}
		offset += count;
	}

	/* Data is valid and fits.  Copy it. */
	offset = 0;
	while (1) {
		int count;

		count = *((unsigned char *)(rr));
		if (!count) break;

		if (offset) {
			*(out + offset) = '.';
			offset++;
		}

		rr++;
		memcpy(out + offset, rr, count);
		rr += count;
		offset += count;
	}

	*(out + offset) = '\0';
	return offset;
}

static int ub_common_wait(rlm_unbound_t const *inst, request_t *request,
			  char const *name, struct ub_result **ub, int async_id)
{
	useconds_t iv, waited;

	iv = inst->timeout > 64 ? 64000 : inst->timeout * 1000;
	ub_process(inst->ub);

	for (waited = 0; (void const *)*ub == (void const *)inst; waited += iv, iv *= 2) {

		if (waited + iv > (useconds_t)inst->timeout * 1000) {
			usleep(inst->timeout * 1000 - waited);
			ub_process(inst->ub);
			break;
		}

		usleep(iv);

		/* Check if already handled by event loop */
		if ((void const *)*ub != (void const *)inst) {
			break;
		}

		/* In case we are running single threaded */
		ub_process(inst->ub);
	}

	if ((void const *)*ub == (void const *)inst) {
		int res;

		REDEBUG2("%s - DNS took too long", name);

		res = ub_cancel(inst->ub, async_id);
		if (res) {
			REDEBUG("%s - ub_cancel: %s", name, ub_strerror(res));
		}
		return -1;
	}

	return 0;
}

static int ub_common_fail(request_t *request, char const *name, struct ub_result *ub)
{
	if (ub->bogus) {
		RWDEBUG("%s - Bogus DNS response", name);
		return -1;
	}

	if (ub->nxdomain) {
		RDEBUG2("%s - NXDOMAIN", name);
		return -1;
	}

	if (!ub->havedata) {
		RDEBUG2("%s - Empty result", name);
		return -1;
	}

	return 0;
}

typedef struct {
	struct ub_result	*result;	//!< The result from the previous operation.
} dns_resume_ctx_t;

/*
static xlat_action_t xlat_ptr(TALLOC_CTX *ctx, fr_cursor_t *out,
			      request_t *request, void const *xlat_inst, void *xlat_thread_inst,
			      fr_value_box_t **in)
{
	if (!*in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input string for attribute reference");
		return XLAT_ACTION_FAIL;
	}

	yield_to

}
*/

/*
 *	Xlat signal callback if an unbound request needs cancelling
 */
static void xlat_unbound_signal(request_t *request, UNUSED void *instance, UNUSED void *thread,
				void *rctx, fr_state_signal_t action)
{
	unbound_request_t	*ur = talloc_get_type_abort(rctx, unbound_request_t);

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Forcefully cancelling pending unbound request");
	talloc_free(ur);
}

/*
 *	Xlat resume callback after unbound has either returned or timed out
 *	Move the parsed results to the xlat output cursor
 */
static xlat_action_t xlat_unbound_resume(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
					 UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					 UNUSED fr_value_box_list_t *in, void *rctx)
{
	fr_value_box_t		*vb;
	unbound_request_t	*ur = talloc_get_type_abort(rctx, unbound_request_t);

#define RCODEERROR(_code, _message) case _code: \
	REDEBUG(_message, ur->t->inst->name); \
	goto error

	/*	Check for unbound errors */
	switch (ur->done) {
	case 1:
		break;

	default:
		REDEBUG("%s - Unknown DNS error", ur->t->inst->name);
	error:
		talloc_free(ur);
		return XLAT_ACTION_FAIL;

	RCODEERROR(0, "%s - No result");
	RCODEERROR(-1, "%s - Query format error");
	RCODEERROR(-2, "%s - DNS server failure");
	RCODEERROR(-3, "%s - Nonexistent domain name");
	RCODEERROR(-4, "%s - DNS server does not support query type");
	RCODEERROR(-5, "%s - DNS server refused query");
	RCODEERROR(-16, "%s - Bogus DNS response");
	RCODEERROR(-32, "%s - Error parsing DNS response");
	}

	/*
	 *	Move parsed results into xlat cursor
	 */
	while ((vb = fr_dlist_pop_head(&ur->list))) {
		fr_dcursor_append(out, vb);
	}

	talloc_free(ur);
	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_unbound_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .single = true, .type = FR_TYPE_UINT16 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Perform a DNS lookup using libunbound
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_unbound(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				  UNUSED void const *xlat_inst, void *xlat_thread_inst,
				  fr_value_box_list_t *in)
{
	fr_value_box_t			*host_vb = fr_dlist_head(in);
	fr_value_box_t			*query_vb = fr_dlist_next(in, host_vb);
	fr_value_box_t			*count_vb = fr_dlist_next(in, query_vb);
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);
	unbound_request_t		*ur;

	if (host_vb->length == 0) {
		REDEBUG("Can't resolve zero length host");
		return XLAT_ACTION_FAIL;
	}

	MEM(ur = talloc_zero(unlang_interpret_frame_talloc_ctx(request), unbound_request_t));

	/*
	 *	Set the maximum number of records we want to return
	 */
	if ((count_vb) && (count_vb->type == FR_TYPE_UINT16) && (count_vb->vb_uint16 > 0)) {
		ur->count = count_vb->vb_uint16;
	} else {
		ur->count = UINT16_MAX;
	}

	ur->request = request;
	ur->t = xt->t;
	ur->out_ctx = ctx;

#define UB_QUERY(_record, _rrvalue, _return, _hasprio) \
	if (strcmp(query_vb->vb_strvalue, _record) == 0) { \
		ur->return_type = _return; \
		ur->has_priority = _hasprio; \
		ub_resolve_event(xt->t->ev_b->ub, host_vb->vb_strvalue, _rrvalue, 1, ur, \
				xlat_unbound_callback, &ur->async_id); \
	}

	UB_QUERY("A", 1, FR_TYPE_IPV4_ADDR, false)
	else UB_QUERY("AAAA", 28, FR_TYPE_IPV6_ADDR, false)
	else UB_QUERY("PTR", 12, FR_TYPE_STRING, false)
	else UB_QUERY("MX", 15, FR_TYPE_STRING, true)
	else UB_QUERY("SRV", 33, FR_TYPE_STRING, true)
	else UB_QUERY("TXT", 16, FR_TYPE_STRING, false)
	else UB_QUERY("CERT", 37, FR_TYPE_OCTETS, false)
	else {
		REDEBUG("Invalid / unsupported DNS query type");
		return XLAT_ACTION_FAIL;
	}

	if (!ur->done) return unlang_xlat_yield(request, xlat_unbound_resume, xlat_unbound_signal, ur);

	/*
	 *	unbound returned before we yielded - run the callback
	 *	This is when serving results from local data
	 */
	return xlat_unbound_resume(NULL, out, request, NULL, NULL, NULL, ur);
}

static int mod_xlat_thread_instantiate(UNUSED void *xlat_inst, void *xlat_thread_inst,
				       UNUSED xlat_exp_t const *exp, void *uctx)
{
	rlm_unbound_t			*inst = talloc_get_type_abort(uctx, rlm_unbound_t);
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);

	xt->inst = inst;
	xt->t = talloc_get_type_abort(module_thread_by_data(inst)->data, rlm_unbound_thread_t);

	return 0;
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_unbound_t	*inst = instance;
	int		res;
	char		k[64]; /* To silence const warns until newer unbound in distros */

	/*
	 *	@todo - move this to the thread-instantiate function
	 */
	inst->ub = ub_ctx_create();
	if (!inst->ub) {
		cf_log_err(conf, "ub_ctx_create failed");
		return -1;
	}

	/*
	 *	Note unbound threads WILL happen with -s option, if it matters.
	 *	We cannot tell from here whether that option is in effect.
	 */
	res = ub_ctx_async(inst->ub, 1);
	if (res) goto error;

	/* Now load the config file, which can override gleaned settings. */
	res = ub_ctx_config(inst->ub, UNCONST(char *, inst->filename));
	if (res) goto error;

	if (unbound_log_init(inst, &inst->u_log, inst->ub) < 0) goto error;

	/*
	 *  Now we need to finalize the context.
	 *
	 *  There's no clean API to just finalize the context made public
	 *  in libunbound.  But we can trick it by trying to delete data
	 *  which as it happens fails quickly and quietly even though the
	 *  data did not exist.
	 */
	strcpy(k, "notar33lsite.foo123.nottld A 127.0.0.1");
	ub_ctx_data_remove(inst->ub, k);
	return 0;

 error:
	cf_log_err(conf, "%s", ub_strerror(res));

	return -1;
}

static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_unbound_t		*inst = talloc_get_type_abort(instance, rlm_unbound_t);
	rlm_unbound_thread_t	*t = talloc_get_type_abort(thread, rlm_unbound_thread_t);
	int			res;

	t->inst = inst;
	if (unbound_io_init(t, &t->ev_b, el) < 0) {
		PERROR("Unable to create unbound event base");
		return -1;
	}

	/*
	 *	Ensure unbound uses threads
	 */
	res = ub_ctx_async(t->ev_b->ub, 1);
	if (res) {
	error:
		PERROR("%s", ub_strerror(res));
		return -1;
	}

	/*
	 *	Load settings from the unbound config file
	 */
	res = ub_ctx_config(t->ev_b->ub, UNCONST(char *, inst->filename));
	if (res) goto error;

	if (unbound_log_init(t, &t->u_log, t->ev_b->ub) < 0) {
		PERROR("Failed to initialise unbound log");
		return -1;
	}

	/*
	 *	The unbound context needs to be "finalised" to fix its settings.
	 *	The API does not expose a method to do this, rather it happens on first
	 *	use.  A quick workround is to delete data which won't be present
	 */
	ub_ctx_data_remove(t->ev_b->ub, "notar33lsite.foo123.nottld A 127.0.0.1");

	return 0;
}

static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_unbound_thread_t	*t = talloc_get_type_abort(thread, rlm_unbound_thread_t);

	talloc_free(t->u_log);
	talloc_free(t->ev_b);

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_unbound_t	*inst = instance;
	xlat_t		*xlat;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (inst->timeout > 10000) {
		cf_log_err(conf, "timeout must be 0 to 10000");
		return -1;
	}

	if(!(xlat = xlat_register(NULL, inst->name, xlat_unbound, true))) return -1;
	xlat_func_args(xlat, xlat_unbound_args);
	xlat_async_thread_instantiate_set(xlat, mod_xlat_thread_instantiate, unbound_xlat_thread_inst_t, NULL, inst);

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_unbound_t *inst = instance;

	ub_process(inst->ub);

	/*
	 *	This can hang/leave zombies currently
	 *	see upstream bug #519
	 *	...so expect valgrind to complain with -m
	 */
	talloc_free(inst->u_log);	/* Free logging first */

	ub_ctx_delete(inst->ub);

	return 0;
}

extern module_t rlm_unbound;
module_t rlm_unbound = {
	.magic			= RLM_MODULE_INIT,
	.name			= "unbound",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_unbound_t),
	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.detach			= mod_detach

	.thread_inst_size	= sizeof(rlm_unbound_thread_t),
	.thread_inst_type	= "rlm_unbound_thread_t",
	.thread_instantiate	= mod_thread_instantiate,
	.thread_detach		= mod_thread_detach,
};
