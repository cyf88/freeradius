/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 *
 * @file unlang/tmpl.c
 * @brief Defines functions for calling tmpl__t asynchronously
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/util/syserror.h>
#include "tmpl_priv.h"
#include <signal.h>

#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/wait.h>
#endif

/*
 *	Clean up everything except the waitpid handler.
 *
 *	If there is a waitpid handler, then this cleanup function MUST
 *	be called after setting the handler.
 */
static void unlang_tmpl_exec_cleanup(request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	if (state->exec.pid) RDEBUG3("Cleaning up exec state for pid %u", state->exec.pid);

	if (state->exec.stdout_fd >= 0) {
		if (fr_event_fd_delete(request->el, state->exec.stdout_fd, FR_EVENT_FILTER_IO) < 0) {
			RPERROR("Failed removing stdout handler");
		}
		close(state->exec.stdout_fd);
		state->exec.stdout_fd = -1;
	}

	if (state->exec.stderr_fd >= 0) {
		if (fr_event_fd_delete(request->el, state->exec.stderr_fd, FR_EVENT_FILTER_IO) < 0) {
			RPERROR("Failed removing stderr handler");
		}
		close(state->exec.stdout_fd);
		state->exec.stdout_fd = -1;
	}

	/*
	 *	It still hasn't exited.  Tell the event loop that we
	 *	need to wait as long as necessary for the PID to exit,
	 *	and that we don't care about the exit status.
	 */
	if (state->exec.pid) {
		(void) fr_event_pid_wait(request->el, request->el, NULL, state->exec.pid, NULL, NULL);
		state->exec.pid = 0;
	}

	if (state->exec.ev) fr_event_timer_delete(&state->exec.ev);
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_tmpl_signal_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] frame		being signalled.
 * @param[in] action		to signal.
 */
static void unlang_tmpl_signal(request_t *request, unlang_stack_frame_t *frame, fr_state_signal_t action)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	if (!state->signal) return;

	state->signal(request, state->rctx, action);

	/*
	 *	If we're cancelled, then kill any child processes, and
	 *	ignore future signals.
	 */
	if (action == FR_SIGNAL_CANCEL) {
		if (state->exec.pid > 0) kill(state->exec.pid, SIGKILL);
		state->exec.failed = true;

		unlang_tmpl_exec_cleanup(request);
		state->signal = NULL;
	}
}

/** Push a tmpl onto the stack for evaluation
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] out		The value_box created from the tmpl.  May be NULL,
 *				in which case the result is discarded.
 * @param[in] request		The current request.
 * @param[in] tmpl		the tmpl to expand
 * @param[in] vps		the input VPs.  May be NULL.  Used only for #TMPL_TYPE_EXEC
 * @param[out] status		where the status of exited programs will be stored.
 */
int unlang_tmpl_push(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request, tmpl_t const *tmpl, fr_pair_list_t *vps, int *status)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_tmpl_t	*state;

	unlang_tmpl_t			*ut;

	static unlang_t tmpl_instruction = {
		.type = UNLANG_TYPE_TMPL,
		.name = "tmpl",
		.debug_name = "tmpl",
		.actions = {
			[RLM_MODULE_REJECT]	= 0,
			[RLM_MODULE_FAIL]	= 0,
			[RLM_MODULE_OK]		= 0,
			[RLM_MODULE_HANDLED]	= 0,
			[RLM_MODULE_INVALID]	= 0,
			[RLM_MODULE_DISALLOW]	= 0,
			[RLM_MODULE_NOTFOUND]	= 0,
			[RLM_MODULE_NOOP]	= 0,
			[RLM_MODULE_UPDATED]	= 0
		},
	};

	MEM(ut = talloc(stack, unlang_tmpl_t));
	*ut = (unlang_tmpl_t){
		.self = tmpl_instruction,
		.tmpl = tmpl
	};

	/*
	 *	Push a new tmpl frame onto the stack
	 */
	if (unlang_interpret_push(request, unlang_tmpl_to_generic(ut),
				  RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP, false) < 0) return -1;

	frame = &stack->frame[stack->depth];
	state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	*state = (unlang_frame_state_tmpl_t) {
		.out = out,
		.ctx = ctx,
		.exec = {
			.vps = vps,
			.status_p = status,
		}
	};
	fr_value_box_list_init(&state->box);

	return 0;
}

/** Wrapper to call a resumption function after a tmpl has been expanded
 *
 *  If the resumption function returns YIELD, then this function is
 *  called repeatedly until the resumption function returns a final
 *  value.
 */
static unlang_action_t unlang_tmpl_resume(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	if (state->out) fr_dlist_move(state->out, &state->box);

	if (state->resume) return state->resume(p_result, request, state->rctx);

	*p_result = RLM_MODULE_OK;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Wrapper to call exec after the program has finished executing
 *
 */
static unlang_action_t unlang_tmpl_exec_wait_final(rlm_rcode_t *p_result, request_t *request,
						   unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	unlang_tmpl_exec_cleanup(request);

	/*
	 *	The exec failed for some internal reason.  We don't
	 *	care about output, and we don't care about the programs exit status.
	 */
	if (state->exec.failed) {
		fr_dlist_talloc_free(&state->box);
		goto resume;
	}

	fr_assert(state->exec.pid == 0);

	if (state->exec.status != 0) {
		if (WIFEXITED(state->exec.status)) {
			RDEBUG("Program failed with status code %d", WEXITSTATUS(state->exec.status));
			state->exec.status = WEXITSTATUS(state->exec.status);

		} else if (WIFSIGNALED(state->exec.status)) {
			RDEBUG("Program exited due to signal with status code %d", WTERMSIG(state->exec.status));
			state->exec.status = -WTERMSIG(state->exec.status);

		} else {
			RDEBUG("Program exited due to unknown status %d", state->exec.status);
			state->exec.status = -state->exec.status;
		}

		fr_assert(fr_dlist_empty(&state->box));
		goto resume;
	}

	/*
	 *	Save the *mangled* exit status, not the raw one.
	 */
	if (state->exec.status_p) *state->exec.status_p = state->exec.status;

	/*
	 *	We might want to just get the status of the program,
	 *	and not care about the output.
	 *
	 *	If we do care about the output, it's unquoted, and tainted.
	 */
	if (state->out) {
		fr_type_t type = FR_TYPE_STRING;
		fr_value_box_t *box;

		/*
		 *	Remove any trailing LF / CR
		 */
		fr_sbuff_trim(&state->exec.stdout_buff, sbuff_char_line_endings);

		fr_value_box_list_init(&state->box);
		MEM(box = fr_value_box_alloc(state->ctx, FR_TYPE_STRING, NULL, true));
		if (fr_value_box_from_str(state->ctx, box, type, NULL,
					  fr_sbuff_buff(&state->exec.stdout_buff),
					  fr_sbuff_used(&state->exec.stdout_buff), 0, true) < 0) {
			talloc_free(box);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
		fr_dlist_insert_head(&state->box, box);
	}

	/*
	 *	Ensure that the callers resume function is called.
	 */
resume:
	frame->process = unlang_tmpl_resume;
	return unlang_tmpl_resume(p_result, request, frame);
}


/** Wrapper to call exec after a tmpl has been expanded
 *
 */
static unlang_action_t unlang_tmpl_exec_wait_resume(rlm_rcode_t *p_result, request_t *request,
						    unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	state->exec.stdout_used = (state->out) ? true : false;
	state->exec.outctx = state;

	/*
	 *	@todo - make the timeout configurable
	 */
	if (fr_exec_wait_start_io(state->ctx, &state->exec, request, &state->box, state->exec.vps,
				  fr_time_delta_from_sec(EXEC_TIMEOUT)) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_dlist_talloc_free(&state->box); /* this is the xlat expansion, and not the output string we want */

	frame->process = unlang_tmpl_exec_wait_final;
	repeatable_set(frame);

	return UNLANG_ACTION_YIELD;
}

/** Wrapper to call exec after a tmpl has been expanded
 *
 */
static unlang_action_t unlang_tmpl_exec_nowait_resume(rlm_rcode_t *p_result, request_t *request,
						      unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	if (fr_exec_nowait(request, &state->box, state->exec.vps) < 0) {
		RPEDEBUG("Failed executing program");
		*p_result = RLM_MODULE_FAIL;

	} else {
		*p_result = RLM_MODULE_OK;
	}

	/*
	 *	state->resume MUST be NULL, as we don't yet support
	 *	exec from unlang_tmpl_push().
	 */

	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_tmpl(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);
	unlang_tmpl_t			*ut = unlang_generic_to_tmpl(frame->instruction);
	xlat_exp_t const		*xlat;

	/*
	 *	If we're not called from unlang_tmpl_push(), then
	 *	ensure that we clean up the resulting value boxes
	 *	and that the list to write the boxes in is initialised.
	 */
	if (!state->ctx) {
		state->ctx = state;
		fr_value_box_list_init(&state->box);
	}

	if (!tmpl_async_required(ut->tmpl)) {
		if (!ut->inline_exec) {
			if (tmpl_aexpand_type(state->ctx, &state->box, FR_TYPE_STRING, request, ut->tmpl, NULL, NULL) < 0) {
				RPEDEBUG("Failed expanding %s", ut->tmpl->name);
				*p_result = RLM_MODULE_FAIL;
			}

			*p_result = RLM_MODULE_OK;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	Inline exec's are only called from in-line
		 *	text in the configuration files.
		 */
		frame->process = unlang_tmpl_exec_nowait_resume;

		repeatable_set(frame);
		if (unlang_xlat_push(state->ctx, &state->box, request, tmpl_xlat(ut->tmpl), false) < 0) {
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_STOP_PROCESSING;
		}
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	XLAT structs are allowed.
	 */
	if (ut->tmpl->type == TMPL_TYPE_XLAT) {
		frame->process = unlang_tmpl_resume;
		repeatable_set(frame);
		if (unlang_xlat_push(state->ctx, &state->box, request, tmpl_xlat(ut->tmpl), false) < 0) {
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_STOP_PROCESSING;
		}
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	if (ut->tmpl->type == TMPL_TYPE_XLAT_UNRESOLVED) {
		REDEBUG("Xlat expansions MUST be fully resolved before being run asynchronously");
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Attribute expansions, etc. don't require YIELD.
	 */
	if (ut->tmpl->type != TMPL_TYPE_EXEC) {
		REDEBUG("Internal error - template '%s' should not require async", ut->tmpl->name);
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	xlat = tmpl_xlat(ut->tmpl);
	fr_assert(xlat);

	/*
	 *	Expand the arguments to the program we're executing.
	 */
	frame->process = unlang_tmpl_exec_wait_resume;
	repeatable_set(frame);
	if (unlang_xlat_push(state->ctx, &state->box, request, xlat, false) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}


void unlang_tmpl_init(void)
{
	unlang_register(UNLANG_TYPE_TMPL,
			   &(unlang_op_t){
				.name = "tmpl",
				.interpret = unlang_tmpl,
				.signal = unlang_tmpl_signal,
				.frame_state_size = sizeof(unlang_frame_state_tmpl_t),
				.frame_state_name = "unlang_frame_state_tmpl_t",
			   });
}
