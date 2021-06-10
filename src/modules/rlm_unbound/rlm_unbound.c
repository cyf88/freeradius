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
	struct ub_ctx		*ub;		//!< Unbound ctx
	rlm_unbound_t		*inst;		//!< Instance data
	unbound_log_t		*u_log;		//!< Unbound log structure
	fr_event_list_t		*el;		//!< Current thread event list
} rlm_unbound_thread_t;

typedef struct {
	rlm_unbound_t		*inst;		//!< Instance data
	rlm_unbound_thread_t	*t;		//!< Thread structure
	request_t		*request;	//!< Current request being processed
	fr_event_timer_t const	*ev;		//!< For timing out the query
	int			async_id;	//!< Id of async query for stopping due to timeout
	struct ub_result	*result;	//!< Result of current query
	int			done;		//!< Indicator that the unbound callback has been called
	fr_type_t		return_type;	//!< Data type to parse result into
	bool			has_priority;	//!< Does the returned data start with a priority field
	uint16_t		count;		//!< Number of results to return
} unbound_xlat_thread_inst_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_unbound_t, filename), .dflt = "${modconfdir}/unbound/default.conf" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, rlm_unbound_t, timeout), .dflt = "3000" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Cleanup events after unbound has either completed or timed out
 */
static void unbound_event_cleanup(unbound_xlat_thread_inst_t *xt)
{
	fr_event_fd_delete(xt->t->el, ub_fd(xt->t->ub), FR_EVENT_FILTER_IO);
	if(xt->ev) fr_event_timer_delete(&xt->ev);
}

/*
 *	Callback sent to libunbound for xlat functions.  Simply links the
 *	new ub_result via a pointer that has been allocated from the heap,
 *	and marks the request as runnable
 */
static void link_ubres(void *my_arg, int err, struct ub_result *result)
{
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(my_arg, unbound_xlat_thread_inst_t);
	xt->done = 1;

	/*
	 *	Note that while result will be NULL on error, we are explicit
	 *	here because that is actually a behavior that is suboptimal
	 *	and only documented in the examples.  It could change.
	 */
	if (err) {
		ERROR("%s", ub_strerror(err));
		xt->result = NULL;
	} else {
		xt->result = result;
	}

	unbound_event_cleanup(xt);

	unlang_interpret_mark_runnable(xt->request);
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

/*
 *	Callback from timeout event.  Cancel the unbound.
 */
static void ub_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(uctx, unbound_xlat_thread_inst_t);
	request_t			*request = xt->request;

	REDEBUG("Timeout waiting for DNS resolution");
	ub_cancel(xt->t->ub, xt->async_id);
	unbound_event_cleanup(xt);

	unlang_interpret_mark_runnable(request);
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

/** Perform a DNS lookup for an A record
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_a(TALLOC_CTX *ctx, char **out, size_t outlen,
		      void const *mod_inst, UNUSED void const *xlat_inst,
		      request_t *request, char const *fmt)
{
	rlm_unbound_t const *inst = mod_inst;
	struct ub_result **ubres;
	int async_id;
	char *fmt2; /* For const warnings.  Keep till new libunbound ships. */

	/* This has to be on the heap, because threads. */
	ubres = talloc(inst, struct ub_result *);

	/* Used and thus impossible value from heap to designate incomplete */
	memcpy(ubres, &mod_inst, sizeof(*ubres));

	fmt2 = talloc_typed_strdup(ctx, fmt);
	ub_resolve_async(inst->ub, fmt2, 1, 1, ubres, link_ubres, &async_id);
	talloc_free(fmt2);

	if (ub_common_wait(inst, request, inst->xlat_a_name, ubres, async_id)) {
		goto error0;
	}

	if (*ubres) {
		if (ub_common_fail(request, inst->xlat_a_name, *ubres)) {
			goto error1;
		}

		if (!inet_ntop(AF_INET, (*ubres)->data[0], *out, outlen)) {
			goto error1;
		};

		ub_resolve_free(*ubres);
		talloc_free(ubres);
		return strlen(*out);
	}

	RWDEBUG("%s - No result", inst->xlat_a_name);

 error1:
	ub_resolve_free(*ubres); /* Handles NULL gracefully */

 error0:
	talloc_free(ubres);
	return -1;
}

/** Perform a DNS lookup for an AAAA record
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_aaaa(TALLOC_CTX *ctx, char **out, size_t outlen,
			 void const *mod_inst, UNUSED void const *xlat_inst,
			 request_t *request, char const *fmt)
{
	rlm_unbound_t const *inst = mod_inst;
	struct ub_result **ubres;
	int async_id;
	char *fmt2; /* For const warnings.  Keep till new libunbound ships. */

	/* This has to be on the heap, because threads. */
	ubres = talloc(inst, struct ub_result *);

	/* Used and thus impossible value from heap to designate incomplete */
	memcpy(ubres, &mod_inst, sizeof(*ubres));

	fmt2 = talloc_typed_strdup(ctx, fmt);
	ub_resolve_async(inst->ub, fmt2, 28, 1, ubres, link_ubres, &async_id);
	talloc_free(fmt2);

	if (ub_common_wait(inst, request, inst->xlat_aaaa_name, ubres, async_id)) {
		goto error0;
	}

	if (*ubres) {
		if (ub_common_fail(request, inst->xlat_aaaa_name, *ubres)) {
			goto error1;
		}
		if (!inet_ntop(AF_INET6, (*ubres)->data[0], *out, outlen)) {
			goto error1;
		};
		ub_resolve_free(*ubres);
		talloc_free(ubres);
		return strlen(*out);
	}

	RWDEBUG("%s - No result", inst->xlat_aaaa_name);

error1:
	ub_resolve_free(*ubres); /* Handles NULL gracefully */

error0:
	talloc_free(ubres);
	return -1;
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
 *	Xlat resume callback after unbound has either returned or timed out
 *	Parse the results and add to the output
 */
static xlat_action_t xlat_unbound_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
					 UNUSED void const *xlat_inst, void *xlat_thread_inst,
					 UNUSED fr_value_box_list_t *in, UNUSED void *rctx)
{
	fr_value_box_t			*vb;
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);
	uint16_t			i = 0;

	if ((xt->done == 0) || (!(xt->result))) {
		RWDEBUG("%s - No result", xt->inst->name);
		return XLAT_ACTION_FAIL;
	}

	/*	Check for unbound errors */
	if (xt->result->bogus) {
		RWDEBUG("%s - Bogus DNS response", xt->inst->name);
	error:
		ub_resolve_free(xt->result);
		return XLAT_ACTION_FAIL;
	}

	if (xt->result->nxdomain) {
		RDEBUG2("%s - NXDOMAIN", xt->inst->name);
		goto error;
	}

	if (!xt->result->havedata) {
		RDEBUG2("%s - Empty result", xt->inst->name);
		goto error;
	}

	/*
	 *	unbound results are in an array of char[].
	 *	The last entry is a NULL pointer.
	 *	Process up to xt->count results, adding each as a separate box.
	 */
	do {
		vb = fr_value_box_alloc_null(ctx);
		switch (xt->return_type) {
		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_OCTETS:
			if (fr_value_box_from_network(ctx, vb, xt->return_type, NULL, (uint8_t *)xt->result->data[i], xt->result->len[i], true) < 0) {
			error2:
				talloc_free(vb);
				goto error;
			}
			break;
		case FR_TYPE_STRING:
		{
			size_t offset = 0;
			if (xt->has_priority) {
				/*
				 *	This result type has a priority before the label
				 *	add the priority first as a separate box
				 */
				fr_value_box_t	*priority_vb;
				if (xt->result->len[i] < 3) {
					REDEBUG("%s - Invalid data returned", xt->inst->name);
					goto error2;
				}
				priority_vb = fr_value_box_alloc_null(ctx);
				if (fr_value_box_from_network(ctx, priority_vb, FR_TYPE_UINT16, NULL, (uint8_t *)xt->result->data[i], 2, true) < 0) {
					talloc_free(priority_vb);
					goto error2;
				}
				fr_dcursor_append(out, priority_vb);
				offset = 2;
			}
			/*	String types require decoding of dns format labels */
			if (rrlabels_tovb(vb, xt->result->data[i] + offset) == XLAT_ACTION_FAIL) goto error2;
		}
			break;
		default:
			goto error2;
		}

		fr_dcursor_append(out, vb);
	} while  ((++i < xt->count) && (xt->result->data[i]));

	ub_resolve_free(xt->result);

	return XLAT_ACTION_DONE;
}

/** Perform a DNS lookup for a PTR record
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_ptr(TALLOC_CTX *ctx, char **out, size_t outlen,
			void const *mod_inst, UNUSED void const *xlat_inst,
			request_t *request, char const *fmt)
{
	rlm_unbound_t const *inst = mod_inst;
	struct ub_result **ubres;
	int async_id;
	char *fmt2; /* For const warnings.  Keep till new libunbound ships. */

	/* This has to be on the heap, because threads. */
	ubres = talloc(inst, struct ub_result *);

	/* Used and thus impossible value from heap to designate incomplete */
	memcpy(ubres, &mod_inst, sizeof(*ubres));

	fmt2 = talloc_typed_strdup(ctx, fmt);
	ub_resolve_async(inst->ub, fmt2, 12, 1, ubres, link_ubres, &async_id);
	talloc_free(fmt2);

	if (ub_common_wait(inst, request, inst->xlat_ptr_name,
			   ubres, async_id)) {
		goto error0;
	}

	if (*ubres) {
		if (ub_common_fail(request, inst->xlat_ptr_name, *ubres)) {
			goto error1;
		}
		if (rrlabels_tostr(*out, (*ubres)->data[0], outlen) < 0) {
			goto error1;
		}
		ub_resolve_free(*ubres);
		talloc_free(ubres);
		return strlen(*out);
	}

	RWDEBUG("%s - No result", inst->xlat_ptr_name);

error1:
	ub_resolve_free(*ubres);  /* Handles NULL gracefully */

error0:
	talloc_free(ubres);
	return -1;
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
	t->el = el;
	t->ub = ub_ctx_create();
	if (!t->ub) {
		PERROR("Unable to create unbound ctx");
		return -1;
	}

	/*
	 *	Ensure unbound uses threads
	 */
	res = ub_ctx_async(t->ub, 1);
	if (res) {
	error:
		PERROR("%s", ub_strerror(res));
		return -1;
	}

	/*
	 *	Load settings from the unbound config file
	 */
	res = ub_ctx_config(t->ub, UNCONST(char *, inst->filename));
	if (res) goto error;

	if (unbound_log_init(t, &t->u_log, t->ub) < 0) {
		PERROR("Failed to initialise unbound log");
		return -1;
	}

	/*
	 *	The unbound context needs to be "finalised" to fix its settings.
	 *	The API does not expose a method to do this, rather it happens on first
	 *	use.  A quick workround is to delete data which won't be present
	 */
	ub_ctx_data_remove(t->ub, "notar33lsite.foo123.nottld A 127.0.0.1");

	return 0;
}

static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_unbound_thread_t	*t = talloc_get_type_abort(thread, rlm_unbound_thread_t);

	ub_process(t->ub);
	talloc_free(t->u_log);
	ub_ctx_delete(t->ub);

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_unbound_t *inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (inst->timeout > 10000) {
		cf_log_err(conf, "timeout must be 0 to 10000");
		return -1;
	}

	MEM(inst->xlat_a_name = talloc_typed_asprintf(inst, "%s-a", inst->name));
	MEM(inst->xlat_aaaa_name = talloc_typed_asprintf(inst, "%s-aaaa", inst->name));
	MEM(inst->xlat_ptr_name = talloc_typed_asprintf(inst, "%s-ptr", inst->name));

	if (xlat_register_legacy(inst, inst->xlat_a_name, xlat_a, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN) ||
	    xlat_register_legacy(inst, inst->xlat_aaaa_name, xlat_aaaa, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN) ||
	    xlat_register_legacy(inst, inst->xlat_ptr_name, xlat_ptr, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN)) {
		cf_log_err(conf, "Failed registering xlats");
		return -1;
	}

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
