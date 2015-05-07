/*
 * valuepair.c	Functions to handle VALUE_PAIRs
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version. either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/regex.h>

#include <ctype.h>

/** Free a VALUE_PAIR
 *
 * @note Do not call directly, use talloc_free instead.
 *
 * @param vp to free.
 * @return 0
 */
static int _pairfree(VALUE_PAIR *vp) {
#ifndef NDEBUG
	vp->vp_integer = FREE_MAGIC;
#endif

#ifdef TALLOC_DEBUG
	talloc_report_depth_cb(NULL, 0, -1, fr_talloc_verify_cb, NULL);
#endif
	return 0;
}

/** Dynamically allocate a new attribute
 *
 * Allocates a new attribute and a new dictionary attr if no DA is provided.
 *
 * @param[in] ctx for allocated memory, usually a pointer to a #RADIUS_PACKET
 * @param[in] da Specifies the dictionary attribute to build the #VALUE_PAIR from.
 * @return
 *	- A new #VALUE_PAIR.
 *	- NULL if an error occurred.
 */
VALUE_PAIR *pairalloc(TALLOC_CTX *ctx, DICT_ATTR const *da)
{
	VALUE_PAIR *vp;

	/*
	 *	Caller must specify a da else we don't know what the attribute type is.
	 */
	if (!da) {
		fr_strerror_printf("Invalid arguments");
		return NULL;
	}

	vp = talloc_zero(ctx, VALUE_PAIR);
	if (!vp) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	vp->da = da;
	vp->op = T_OP_EQ;
	vp->tag = TAG_ANY;
	vp->type = VT_NONE;

	vp->vp_length = da->flags.length;

	talloc_set_destructor(vp, _pairfree);

	return vp;
}

/** Create a new valuepair
 *
 * If attr and vendor match a dictionary entry then a VP with that #DICT_ATTR
 * will be returned.
 *
 * If attr or vendor are uknown will call dict_attruknown to create a dynamic
 * #DICT_ATTR of #PW_TYPE_OCTETS.
 *
 * Which type of #DICT_ATTR the #VALUE_PAIR was created with can be determined by
 * checking @verbatim vp->da->flags.is_unknown @endverbatim.
 *
 * @param[in] ctx for allocated memory, usually a pointer to a #RADIUS_PACKET.
 * @param[in] attr number.
 * @param[in] vendor number.
 * @return
 *	- A new #VALUE_PAIR.
 *	- NULL on error.
 */
VALUE_PAIR *paircreate(TALLOC_CTX *ctx, unsigned int attr, unsigned int vendor)
{
	DICT_ATTR const *da;

	da = dict_attrbyvalue(attr, vendor);
	if (!da) {
		da = dict_unknown_afrom_fields(ctx, attr, vendor);
		if (!da) {
			return NULL;
		}
	}

	return pairalloc(ctx, da);
}

/** Free memory used by a valuepair list.
 *
 * @todo TLV: needs to free all dependents of each VP freed.
 */
void pairfree(VALUE_PAIR **vps)
{
	VALUE_PAIR	*vp;
	vp_cursor_t	cursor;

	if (!vps || !*vps) {
		return;
	}

	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VERIFY_VP(vp);
		talloc_free(vp);
	}

	*vps = NULL;
}

/** Mark malformed or unrecognised attributed as unknown
 *
 * @param vp to change DICT_ATTR of.
 * @return
 *	- 0 on success (or if already unknown).
 *	- -1 on failure.
 */
int pair2unknown(VALUE_PAIR *vp)
{
	DICT_ATTR const *da;

	VERIFY_VP(vp);
	if (vp->da->flags.is_unknown) {
		return 0;
	}

	da = dict_unknown_afrom_fields(vp, vp->da->attr, vp->da->vendor);
	if (!da) {
		return -1;
	}

	vp->da = da;

	return 0;
}

/** Find the pair with the matching DAs
 *
 */
VALUE_PAIR *pair_find_by_da(VALUE_PAIR *vp, DICT_ATTR const *da, int8_t tag)
{
	vp_cursor_t 	cursor;

	if(!fr_assert(da)) {
		 return NULL;
	}

	(void) fr_cursor_init(&cursor, &vp);
	return fr_cursor_next_by_da(&cursor, da, tag);
}


/** Find the pair with the matching attribute
 *
 * @todo should take DAs and do a pointer comparison.
 */
VALUE_PAIR *pairfind(VALUE_PAIR *vp, unsigned int attr, unsigned int vendor, int8_t tag)
{
	vp_cursor_t 	cursor;

	/* List head may be NULL if it contains no VPs */
	if (!vp) return NULL;

	VERIFY_LIST(vp);

	(void) fr_cursor_init(&cursor, &vp);
	return fr_cursor_next_by_num(&cursor, attr, vendor, tag);
}

/** Delete matching pairs
 *
 * Delete matching pairs from the attribute list.
 *
 * @param[in,out] first VP in list.
 * @param[in] attr to match.
 * @param[in] vendor to match.
 * @param[in] tag to match. TAG_ANY matches any tag, TAG_NONE matches tagless VPs.
 *
 * @todo should take DAs and do a point comparison.
 */
void pairdelete(VALUE_PAIR **first, unsigned int attr, unsigned int vendor,
		int8_t tag)
{
	VALUE_PAIR *i, *next;
	VALUE_PAIR **last = first;

	for(i = *first; i; i = next) {
		VERIFY_VP(i);
		next = i->next;
		if ((i->da->attr == attr) && (i->da->vendor == vendor) &&
		    (!i->da->flags.has_tag || TAG_EQ(tag, i->tag))) {
			*last = next;
			talloc_free(i);
		} else {
			last = &i->next;
		}
	}
}

/** Add a VP to the end of the list.
 *
 * Locates the end of 'first', and links an additional VP 'add' at the end.
 *
 * @param[in] first VP in linked list. Will add new VP to the end of this list.
 * @param[in] add VP to add to list.
 */
void pairadd(VALUE_PAIR **first, VALUE_PAIR *add)
{
	VALUE_PAIR *i;

	if (!add) return;

	VERIFY_VP(add);

	if (*first == NULL) {
		*first = add;
		return;
	}

	for (i = *first; i->next; i = i->next) {
#ifdef WITH_VERIFY_PTR
		VERIFY_VP(i);
		/*
		 *	The same VP should never by added multiple times
		 *	to the same list.
		 */
		fr_assert(i != add);
#endif
	}

	i->next = add;
}

/** Replace all matching VPs
 *
 * Walks over 'first', and replaces the first VP that matches 'replace'.
 *
 * @note Memory used by the VP being replaced will be freed.
 * @note Will not work with unknown attributes.
 *
 * @param[in,out] first VP in linked list. Will search and replace in this list.
 * @param[in] replace VP to replace.
 */
void pairreplace(VALUE_PAIR **first, VALUE_PAIR *replace)
{
	VALUE_PAIR *i, *next;
	VALUE_PAIR **prev = first;

	VERIFY_VP(replace);

	if (*first == NULL) {
		*first = replace;
		return;
	}

	/*
	 *	Not an empty list, so find item if it is there, and
	 *	replace it. Note, we always replace the first one, and
	 *	we ignore any others that might exist.
	 */
	for(i = *first; i; i = next) {
		VERIFY_VP(i);
		next = i->next;

		/*
		 *	Found the first attribute, replace it,
		 *	and return.
		 */
		if ((i->da == replace->da) && (!i->da->flags.has_tag || TAG_EQ(replace->tag, i->tag))) {
			*prev = replace;

			/*
			 *	Should really assert that replace->next == NULL
			 */
			replace->next = next;
			talloc_free(i);
			return;
		}

		/*
		 *	Point to where the attribute should go.
		 */
		prev = &i->next;
	}

	/*
	 *	If we got here, we didn't find anything to replace, so
	 *	stopped at the last item, which we just append to.
	 */
	*prev = replace;
}

int8_t attrtagcmp(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a;
	VALUE_PAIR const *my_b = b;

	VERIFY_VP(my_a);
	VERIFY_VP(my_b);

	uint8_t cmp;

	cmp = fr_pointer_cmp(my_a->da, my_b->da);
	if (cmp != 0) return cmp;

	if (my_a->tag < my_b->tag) return -1;

	if (my_a->tag > my_b->tag) return 1;

	return 0;
}

static void pairsort_split(VALUE_PAIR *source, VALUE_PAIR **front, VALUE_PAIR **back)
{
	VALUE_PAIR *fast;
	VALUE_PAIR *slow;

	/*
	 *	Stopping condition - no more elements left to split
	 */
	if (!source || !source->next) {
		*front = source;
		*back = NULL;

		return;
	}

	/*
	 *	Fast advances twice as fast as slow, so when it gets to the end,
	 *	slow will point to the middle of the linked list.
	 */
	slow = source;
	fast = source->next;

	while (fast) {
		fast = fast->next;
		if (fast) {
			slow = slow->next;
			fast = fast->next;
		}
	}

	*front = source;
	*back = slow->next;
	slow->next = NULL;
}

static VALUE_PAIR *pairsort_merge(VALUE_PAIR *a, VALUE_PAIR *b, fr_cmp_t cmp)
{
	VALUE_PAIR *result = NULL;

	if (!a) return b;
	if (!b) return a;

	/*
	 *	Compare the DICT_ATTRs and tags
	 */
	if (cmp(a, b) <= 0) {
		result = a;
		result->next = pairsort_merge(a->next, b, cmp);
	} else {
		result = b;
		result->next = pairsort_merge(a, b->next, cmp);
	}

	return result;
}

/** Sort a linked list of VALUE_PAIRs using merge sort
 *
 * @param[in,out] vps List of VALUE_PAIRs to sort.
 * @param[in] cmp to sort with
 */
void pairsort(VALUE_PAIR **vps, fr_cmp_t cmp)
{
	VALUE_PAIR *head = *vps;
	VALUE_PAIR *a;
	VALUE_PAIR *b;

	/*
	 *	If there's 0-1 elements it must already be sorted.
	 */
	if (!head || !head->next) {
		return;
	}

	pairsort_split(head, &a, &b);	/* Split into sublists */
	pairsort(&a, cmp);		/* Traverse left */
	pairsort(&b, cmp);		/* Traverse right */

	/*
	 *	merge the two sorted lists together
	 */
	*vps = pairsort_merge(a, b, cmp);
}

/** Write an error to the library errorbuff detailing the mismatch
 *
 * Retrieve output with fr_strerror();
 *
 * @todo add thread specific talloc contexts.
 *
 * @param ctx a hack until we have thread specific talloc contexts.
 * @param failed pair of attributes which didn't match.
 */
void pairvalidate_debug(TALLOC_CTX *ctx, VALUE_PAIR const *failed[2])
{
	VALUE_PAIR const *filter = failed[0];
	VALUE_PAIR const *list = failed[1];

	char *value, *str;

	(void) fr_strerror();	/* Clear any existing messages */

	if (!fr_assert(!(!filter && !list))) return;

	if (!list) {
		if (!filter) return;
		fr_strerror_printf("Attribute \"%s\" not found in list", filter->da->name);
		return;
	}

	if (!filter || (filter->da != list->da)) {
		fr_strerror_printf("Attribute \"%s\" not found in filter", list->da->name);
		return;
	}

	if (!TAG_EQ(filter->tag, list->tag)) {
		fr_strerror_printf("Attribute \"%s\" tag \"%i\" didn't match filter tag \"%i\"",
				   list->da->name, list->tag, filter->tag);
		return;
	}


	value = vp_aprints_value(ctx, list, '"');
	str = vp_aprints(ctx, filter, '"');

	fr_strerror_printf("Attribute value \"%s\" didn't match filter: %s", value, str);

	talloc_free(str);
	talloc_free(value);

	return;
}

/** Uses paircmp to verify all VALUE_PAIRs in list match the filter defined by check
 *
 * @note will sort both filter and list in place.
 *
 * @param failed pointer to an array to write the pointers of the filter/list attributes that didn't match.
 *	  May be NULL.
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool pairvalidate(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list)
{
	vp_cursor_t filter_cursor;
	vp_cursor_t list_cursor;

	VALUE_PAIR *check, *match;

	if (!filter && !list) {
		return true;
	}

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	pairsort(&filter, attrtagcmp);
	pairsort(&list, attrtagcmp);

	check = fr_cursor_init(&filter_cursor, &filter);
	match = fr_cursor_init(&list_cursor, &list);
	while (match || check) {
		/*
		 *	Lists are of different lengths
		 */
		if (!match || !check) goto mismatch;

		/*
		 *	The lists are sorted, so if the first
		 *	attributes aren't of the same type, then we're
		 *	done.
		 */
		if (!ATTRIBUTE_EQ(check, match)) goto mismatch;

		/*
		 *	They're of the same type, but don't have the
		 *	same values.  This is a problem.
		 *
		 *	Note that the RFCs say that for attributes of
		 *	the same type, order is important.
		 */
		if (paircmp(check, match) != 1) goto mismatch;

		check = fr_cursor_next(&filter_cursor);
		match = fr_cursor_next(&list_cursor);
	}

	return true;

mismatch:
	if (failed) {
		failed[0] = check;
		failed[1] = match;
	}
	return false;
}

/** Uses paircmp to verify all VALUE_PAIRs in list match the filter defined by check
 *
 * @note will sort both filter and list in place.
 *
 * @param failed pointer to an array to write the pointers of the filter/list attributes that didn't match.
 *	  May be NULL.
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool pairvalidate_relaxed(VALUE_PAIR const *failed[2], VALUE_PAIR *filter, VALUE_PAIR *list)
{
	vp_cursor_t filter_cursor;
	vp_cursor_t list_cursor;

	VALUE_PAIR *check, *last_check = NULL, *match = NULL;

	if (!filter && !list) {
		return true;
	}

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	pairsort(&filter, attrtagcmp);
	pairsort(&list, attrtagcmp);

	fr_cursor_init(&list_cursor, &list);
	for (check = fr_cursor_init(&filter_cursor, &filter);
	     check;
	     check = fr_cursor_next(&filter_cursor)) {
		/*
		 *	Were processing check attributes of a new type.
		 */
		if (!ATTRIBUTE_EQ(last_check, check)) {
			/*
			 *	Record the start of the matching attributes in the pair list
			 *	For every other operator we require the match to be present
			 */
			match = fr_cursor_next_by_da(&list_cursor, check->da, check->tag);
			if (!match) {
				if (check->op == T_OP_CMP_FALSE) continue;
				goto mismatch;
			}

			fr_cursor_init(&list_cursor, &match);
			last_check = check;
		}

		/*
		 *	Now iterate over all attributes of the same type.
		 */
		for (match = fr_cursor_first(&list_cursor);
		     ATTRIBUTE_EQ(match, check);
		     match = fr_cursor_next(&list_cursor)) {
			/*
			 *	This attribute passed the filter
			 */
			if (!paircmp(check, match)) goto mismatch;
		}
	}

	return true;

mismatch:
	if (failed) {
		failed[0] = check;
		failed[1] = match;
	}
	return false;
}

/** Copy a single valuepair
 *
 * Allocate a new valuepair and copy the da from the old vp.
 *
 * @param[in] ctx for talloc
 * @param[in] vp to copy.
 * @return
 *	- A copy of the input VP.
 *	- NULL on error.
 */
VALUE_PAIR *paircopyvp(TALLOC_CTX *ctx, VALUE_PAIR const *vp)
{
	VALUE_PAIR *n;

	if (!vp) return NULL;

	VERIFY_VP(vp);

	n = pairalloc(ctx, vp->da);
	if (!n) return NULL;

	memcpy(n, vp, sizeof(*n));

	/*
	 *	If the DA is unknown, steal "n" to "ctx".  This does
	 *	nothing for "n", but will also copy the unknown "da".
	 */
	if (n->da->flags.is_unknown) {
		pairsteal(ctx, n);
	}

	n->next = NULL;

	/*
	 *	If it's an xlat, copy the raw string and return early,
	 *	so we don't pre-expand or otherwise mangle the VALUE_PAIR.
	 */
	if (vp->type == VT_XLAT) {
		n->xlat = talloc_typed_strdup(n, n->xlat);
		return n;
	}

	switch (vp->da->type) {
	case PW_TYPE_TLV:
	case PW_TYPE_OCTETS:
		n->vp_octets = NULL;	/* else pairmemcpy will free vp's value */
		pairmemcpy(n, vp->vp_octets, n->vp_length);
		break;

	case PW_TYPE_STRING:
		n->vp_strvalue = NULL;	/* else pairstrnpy will free vp's value */
		pairbstrncpy(n, vp->vp_strvalue, n->vp_length);
		break;

	default:
		break;
	}

	return n;
}

/** Copy a pairlist
 *
 * Copy all pairs from 'from' regardless of tag, attribute or vendor.
 *
 * @param[in] ctx for new #VALUE_PAIR (s) to be allocated in.
 * @param[in] from whence to copy #VALUE_PAIR (s).
 * @return the head of the new #VALUE_PAIR list or NULL on error.
 */
VALUE_PAIR *paircopy(TALLOC_CTX *ctx, VALUE_PAIR *from)
{
	vp_cursor_t src, dst;

	VALUE_PAIR *out = NULL, *vp;

	fr_cursor_init(&dst, &out);
	for (vp = fr_cursor_init(&src, &from);
	     vp;
	     vp = fr_cursor_next(&src)) {
		VERIFY_VP(vp);
		vp = paircopyvp(ctx, vp);
		if (!vp) {
			pairfree(&out);
			return NULL;
		}
		fr_cursor_insert(&dst, vp); /* paircopy sets next pointer to NULL */
	}

	return out;
}

/** Copy matching pairs
 *
 * Copy pairs of a matching attribute number, vendor number and tag from the
 * the input list to a new list, and returns the head of this list.
 *
 * @param[in] ctx for talloc
 * @param[in] from whence to copy #VALUE_PAIR.
 * @param[in] attr to match, if 0 input list will not be filtered by attr.
 * @param[in] vendor to match.
 * @param[in] tag to match, #TAG_ANY matches any tag, #TAG_NONE matches tagless VPs.
 * @return the head of the new #VALUE_PAIR list or NULL on error.
 */
VALUE_PAIR *paircopy_by_num(TALLOC_CTX *ctx, VALUE_PAIR *from, unsigned int attr, unsigned int vendor, int8_t tag)
{
	vp_cursor_t src, dst;

	VALUE_PAIR *out = NULL, *vp;

	fr_cursor_init(&dst, &out);
	for (vp = fr_cursor_init(&src, &from);
	     vp;
	     vp = fr_cursor_next(&src)) {
		VERIFY_VP(vp);

		if ((vp->da->attr != attr) || (vp->da->vendor != vendor)) {
			continue;
		}

		if (vp->da->flags.has_tag && !TAG_EQ(tag, vp->tag)) {
			continue;
		}

		vp = paircopyvp(ctx, vp);
		if (!vp) {
			pairfree(&out);
			return NULL;
		}
		fr_cursor_insert(&dst, vp);
	}

	return out;
}

/** Steal one VP
 *
 * @param[in] ctx to move VALUE_PAIR into
 * @param[in] vp VALUE_PAIR to move into the new context.
 */
void pairsteal(TALLOC_CTX *ctx, VALUE_PAIR *vp)
{
	(void) talloc_steal(ctx, vp);

	/*
	 *	The DA may be unknown.  If we're stealing the VPs to a
	 *	different context, copy the unknown DA.  We use the VP
	 *	as a context here instead of "ctx", so that when the
	 *	VP is freed, so is the DA.
	 *
	 *	Since we have no introspection into OTHER VPs using
	 *	the same DA, we can't have multiple VPs use the same
	 *	DA.  So we might as well tie it to this VP.
	 */
	if (vp->da->flags.is_unknown) {
		DICT_ATTR *da;
		char *p;
		size_t size;

		size = talloc_get_size(vp->da);

		p = talloc_zero_array(vp, char, size);
		da = (DICT_ATTR *) p;
		talloc_set_type(p, DICT_ATTR);
		memcpy(da, vp->da, size);
		vp->da = da;
	}
}

/** Move pairs from source list to destination list respecting operator
 *
 * @note This function does some additional magic that's probably not needed
 *	 in most places. Consider using radius_pairmove in server code.
 *
 * @note pairfree should be called on the head of the source list to free
 *	 unmoved attributes (if they're no longer needed).
 *
 * @note Does not respect tags when matching.
 *
 * @param[in] ctx for talloc
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 *
 * @see radius_pairmove
 */
void pairmove(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from)
{
	VALUE_PAIR *i, *found;
	VALUE_PAIR *head_new, **tail_new;
	VALUE_PAIR **tail_from;

	if (!to || !from || !*from) return;

	/*
	 *	We're editing the "to" list while we're adding new
	 *	attributes to it.  We don't want the new attributes to
	 *	be edited, so we create an intermediate list to hold
	 *	them during the editing process.
	 */
	head_new = NULL;
	tail_new = &head_new;

	/*
	 *	We're looping over the "from" list, moving some
	 *	attributes out, but leaving others in place.
	 */
	tail_from = from;
	while ((i = *tail_from) != NULL) {
		VALUE_PAIR *j;

		VERIFY_VP(i);

		/*
		 *	We never move Fall-Through.
		 */
		if (!i->da->vendor && i->da->attr == PW_FALL_THROUGH) {
			tail_from = &(i->next);
			continue;
		}

		/*
		 *	Unlike previous versions, we treat all other
		 *	attributes as normal.  i.e. there's no special
		 *	treatment for passwords or Hint.
		 */

		switch (i->op) {
		/*
		 *	Anything else are operators which
		 *	shouldn't occur.  We ignore them, and
		 *	leave them in place.
		 */
		default:
			tail_from = &(i->next);
			continue;

		/*
		 *	Add it to the "to" list, but only if
		 *	it doesn't already exist.
		 */
		case T_OP_EQ:
			found = pair_find_by_da(*to, i->da, TAG_ANY);
			if (!found) goto do_add;

			tail_from = &(i->next);
			continue;

		/*
		 *	Add it to the "to" list, and delete any attribute
		 *	of the same vendor/attr which already exists.
		 */
		case T_OP_SET:
			found = pair_find_by_da(*to, i->da, TAG_ANY);
			if (!found) goto do_add;

			/*
			 *	Do NOT call pairdelete() here,
			 *	due to issues with re-writing
			 *	"request->username".
			 *
			 *	Everybody calls pairmove, and
			 *	expects it to work.  We can't
			 *	update request->username here,
			 *	so instead we over-write the
			 *	vp that it's pointing to.
			 */
			switch (found->da->type) {
			default:
				j = found->next;
				memcpy(found, i, sizeof(*found));
				found->next = j;
				break;

			case PW_TYPE_TLV:
				pairmemsteal(found, i->vp_tlv);
				i->vp_tlv = NULL;
				break;

			case PW_TYPE_OCTETS:
				pairmemsteal(found, i->vp_octets);
				i->vp_octets = NULL;
				break;

			case PW_TYPE_STRING:
				pairstrsteal(found, i->vp_strvalue);
				i->vp_strvalue = NULL;
				found->tag = i->tag;
				break;
			}

			/*
			 *	Delete *all* of the attributes
			 *	of the same number.
			 */
			pairdelete(&found->next,
				   found->da->attr,
				   found->da->vendor, TAG_ANY);

			/*
			 *	Remove this attribute from the
			 *	"from" list.
			 */
			*tail_from = i->next;
			i->next = NULL;
			pairfree(&i);
			continue;

		/*
		 *	Move it from the old list and add it
		 *	to the new list.
		 */
		case T_OP_ADD:
	do_add:
			*tail_from = i->next;
			i->next = NULL;
			*tail_new = i;
			pairsteal(ctx, i);
			tail_new = &(i->next);
			continue;
		}
	} /* loop over the "from" list. */

	/*
	 *	Take the "new" list, and append it to the "to" list.
	 */
	pairadd(to, head_new);
}

/** Move matching pairs between VALUE_PAIR lists
 *
 * Move pairs of a matching attribute number, vendor number and tag from the
 * the input list to the output list.
 *
 * @note pairs which are moved have their parent changed to ctx.
 *
 * @note pairfree should be called on the head of the old list to free unmoved
	 attributes (if they're no longer needed).
 *
 * @param[in] ctx for talloc
 * @param[in,out] to destination list.
 * @param[in,out] from source list.
 * @param[in] attr to match. If attribute PW_VENDOR_SPECIFIC and vendor 0,
 *	will match (and therefore copy) only VSAs.
 *	If attribute 0 and vendor 0  will match (and therefore copy) all
 *	attributes.
 * @param[in] vendor to match.
 * @param[in] tag to match, TAG_ANY matches any tag, TAG_NONE matches tagless VPs.
 */
void pairfilter(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR **from, unsigned int attr, unsigned int vendor, int8_t tag)
{
	VALUE_PAIR *to_tail, *i, *next;
	VALUE_PAIR *iprev = NULL;

	/*
	 *	Find the last pair in the "to" list and put it in "to_tail".
	 *
	 *	@todo: replace the "if" with "VALUE_PAIR **tail"
	 */
	if (*to != NULL) {
		to_tail = *to;
		for(i = *to; i; i = i->next) {
			VERIFY_VP(i);
			to_tail = i;
		}
	} else
		to_tail = NULL;

	/*
	 *	Attr/vendor of 0 means "move them all".
	 *	It's better than "pairadd(foo,bar);bar=NULL"
	 */
	if ((vendor == 0) && (attr == 0)) {
		if (*to) {
			to_tail->next = *from;
		} else {
			*to = *from;
		}

		for (i = *from; i; i = i->next) {
			pairsteal(ctx, i);
		}

		*from = NULL;
		return;
	}

	for(i = *from; i; i = next) {
		VERIFY_VP(i);
		next = i->next;

		if (i->da->flags.has_tag && !TAG_EQ(tag, i->tag)) {
			iprev = i;
			continue;
		}

		/*
		 *	vendor=0, attr = PW_VENDOR_SPECIFIC means
		 *	"match any vendor attribute".
		 */
		if ((vendor == 0) && (attr == PW_VENDOR_SPECIFIC)) {
			/*
			 *	It's a VSA: move it over.
			 */
			if (i->da->vendor != 0) goto move;

			/*
			 *	It's Vendor-Specific: move it over.
			 */
			if (i->da->attr == attr) goto move;

			/*
			 *	It's not a VSA: ignore it.
			 */
			iprev = i;
			continue;
		}

		/*
		 *	If it isn't an exact match, ignore it.
		 */
		if (!((i->da->vendor == vendor) && (i->da->attr == attr))) {
			iprev = i;
			continue;
		}

	move:
		/*
		 *	Remove the attribute from the "from" list.
		 */
		if (iprev)
			iprev->next = next;
		else
			*from = next;

		/*
		 *	Add the attribute to the "to" list.
		 */
		if (to_tail)
			to_tail->next = i;
		else
			*to = i;
		to_tail = i;
		i->next = NULL;
		pairsteal(ctx, i);
	}
}

/** Convert string value to native attribute value
 *
 * @param vp to assign value to.
 * @param value string to convert. Binary safe for variable length values if len is provided.
 * @param inlen may be < 0 in which case strlen(len) is used to determine length, else inline
 *	  should be the length of the string or sub string to parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int pairparsevalue(VALUE_PAIR *vp, char const *value, size_t inlen)
{
	ssize_t ret;
	PW_TYPE type;
	VERIFY_VP(vp);

	if (!value) return -1;

	type = vp->da->type;

	/*
	 *	We presume that the input data is from a double quoted
	 *	string, and needs escaping
	 */
	ret = value_data_from_str(vp, &vp->data, &type, vp->da, value, inlen, '"');
	if (ret < 0) return -1;

	/*
	 *	If we parsed to a different type than the DA associated with
	 *	the VALUE_PAIR we now need to fixup the DA.
	 */
	if (type != vp->da->type) {
		DICT_ATTR const *da;

		da = dict_attrbytype(vp->da->attr, vp->da->vendor, type);
		if (!da) {
			fr_strerror_printf("Cannot find %s variant of attribute \"%s\"",
					   fr_int2str(dict_attr_types, type, "<INVALID>"), vp->da->name);
			return -1;
		}
		vp->da = da;
	}

	vp->vp_length = ret;
	vp->type = VT_DATA;

	VERIFY_VP(vp);

	return 0;
}

/** Use simple heuristics to create an #VALUE_PAIR from an unknown address string
 *
 * If a #DICT_ATTR is not provided for the address type, parsing will fail with
 * and error.
 *
 * @param ctx to allocate VP in.
 * @param value IPv4/IPv6 address/prefix string.
 * @param ipv4 dictionary attribute to use for an IPv4 address.
 * @param ipv6 dictionary attribute to use for an IPv6 address.
 * @param ipv4_prefix dictionary attribute to use for an IPv4 prefix.
 * @param ipv6_prefix dictionary attribute to use for an IPv6 prefix.
 * @return NULL on error, or new #VALUE_PAIR.
 */
VALUE_PAIR *pairmake_ip(TALLOC_CTX *ctx, char const *value, DICT_ATTR *ipv4, DICT_ATTR *ipv6,
			DICT_ATTR *ipv4_prefix, DICT_ATTR *ipv6_prefix)
{
	VALUE_PAIR *vp;
	DICT_ATTR *da = NULL;

	if (!fr_assert(ipv4 || ipv6 || ipv4_prefix || ipv6_prefix)) {
		return NULL;
	}

	/* No point in repeating the work of pairparsevalue */
	if (strchr(value, ':')) {
		if (strchr(value, '/')) {
			da = ipv6_prefix;
			goto finish;
		}

		da = ipv6;
		goto finish;
	}

	if (strchr(value, '/')) {
		da = ipv4_prefix;
		goto finish;
	}

	if (ipv4) {
		da = ipv4;
		goto finish;
	}

	fr_strerror_printf("Invalid IP value specified, allowed types are %s%s%s%s",
			   ipv4 ? "ipaddr " : "", ipv6 ? "ipv6addr " : "",
			   ipv4_prefix ? "ipv4prefix " : "", ipv6_prefix ? "ipv6prefix" : "");

finish:
	vp = pairalloc(ctx, da);
	if (!vp) return NULL;
	if (pairparsevalue(vp, value, -1) < 0) {
		talloc_free(vp);
		return NULL;
	}

	return vp;
}


static VALUE_PAIR *pair_unknown2known(VALUE_PAIR *vp, DICT_ATTR const *da)
{
	ssize_t len;
	VALUE_PAIR *vp2;

	len = data2vp(NULL, NULL, NULL, NULL, da,
		      vp->vp_octets, vp->vp_length, vp->vp_length,
		      &vp2);
	if (len < 0) return vp; /* it's really unknown */

	if (vp2->da->flags.is_unknown) {
		pairfree(&vp2);
		return vp;
	}

	/*
	 *	Didn't parse all of it.  Return the "unknown" one.
	 *
	 *	FIXME: it COULD have parsed 2 attributes and
	 *	then not the third, so returning 2 "knowns"
	 *	and 1 "unknown" is likely preferable.
	 */
	if ((size_t) len < vp->vp_length) {
		pairfree(&vp2);
		return vp;
	}

	pairsteal(talloc_parent(vp), vp2);
	pairfree(&vp);
	return vp2;
}

/** Create a valuepair from an ASCII attribute and value
 *
 * Where the attribute name is in the form:
 *  - Attr-%d
 *  - Attr-%d.%d.%d...
 *  - Vendor-%d-Attr-%d
 *  - VendorName-Attr-%d
 *
 * @param ctx for talloc
 * @param attribute name to parse.
 * @param value to parse (must be a hex string).
 * @param op to assign to new valuepair.
 * @return new #VALUE_PAIR or NULL on error.
 */
static VALUE_PAIR *pairmake_any(TALLOC_CTX *ctx,
				char const *attribute, char const *value,
				FR_TOKEN op)
{
	VALUE_PAIR	*vp;
	DICT_ATTR const *da;

	uint8_t 	*data;
	size_t		size;

	da = dict_unknown_afrom_str(ctx, attribute);
	if (!da) return NULL;

	/*
	 *	Unknown attributes MUST be of type 'octets'
	 */
	if (value && (strncasecmp(value, "0x", 2) != 0)) {
		fr_strerror_printf("Unknown attribute \"%s\" requires a hex "
				   "string, not \"%s\"", attribute, value);

		dict_attr_free(&da);
		return NULL;
	}

	/*
	 *	We've now parsed the attribute properly, Let's create
	 *	it.  This next stop also looks the attribute up in the
	 *	dictionary, and creates the appropriate type for it.
	 */
	vp = pairalloc(ctx, da);
	if (!vp) {
		dict_attr_free(&da);
		return NULL;
	}

	vp->op = (op == 0) ? T_OP_EQ : op;

	if (!value) return vp;

	size = strlen(value + 2);
	vp->vp_length = size >> 1;
	data = talloc_array(vp, uint8_t, vp->vp_length);

	if (fr_hex2bin(data, vp->vp_length, value + 2, size) != vp->vp_length) {
		fr_strerror_printf("Invalid hex string");
		talloc_free(vp);
		return NULL;
	}

	vp->vp_octets = data;
	vp->type = VT_DATA;

	/*
	 *	Convert unknowns to knowns
	 */
	da = dict_attrbyvalue(vp->da->attr, vp->da->vendor);
	if (da) {
		return pair_unknown2known(vp, da);
	}

	return vp;
}


/** Create a #VALUE_PAIR from ASCII strings
 *
 * Converts an attribute string identifier (with an optional tag qualifier)
 * and value string into a #VALUE_PAIR.
 *
 * The string value is parsed according to the type of #VALUE_PAIR being created.
 *
 * @param[in] ctx for talloc.
 * @param[in] vps list where the attribute will be added (optional)
 * @param[in] attribute name.
 * @param[in] value attribute value (may be NULL if value will be set later).
 * @param[in] op to assign to new #VALUE_PAIR.
 * @return a new #VALUE_PAIR.
 */
VALUE_PAIR *pairmake(TALLOC_CTX *ctx, VALUE_PAIR **vps,
		     char const *attribute, char const *value, FR_TOKEN op)
{
	DICT_ATTR const *da;
	VALUE_PAIR	*vp;
	char		*tc, *ts;
	int8_t		tag;
	bool		found_tag;
	char		buffer[256];
	char const	*attrname = attribute;

	/*
	 *    Check for tags in 'Attribute:Tag' format.
	 */
	found_tag = false;
	tag = TAG_ANY;

	ts = strrchr(attribute, ':');
	if (ts && !ts[1]) {
		fr_strerror_printf("Invalid tag for attribute %s", attribute);
		return NULL;
	}

	if (ts && ts[1]) {
		strlcpy(buffer, attribute, sizeof(buffer));
		attrname = buffer;
		ts = strrchr(attrname, ':');
		if (!ts) return NULL;

		 /* Colon found with something behind it */
		 if (ts[1] == '*' && ts[2] == 0) {
			 /* Wildcard tag for check items */
			 tag = TAG_ANY;
			 *ts = '\0';
		 } else if ((ts[1] >= '0') && (ts[1] <= '9')) {
			 /* It's not a wild card tag */
			 tag = strtol(ts + 1, &tc, 0);
			 if (tc && !*tc && TAG_VALID_ZERO(tag))
				 *ts = '\0';
			 else tag = TAG_ANY;
		 } else {
			 fr_strerror_printf("Invalid tag for attribute %s", attribute);
			 return NULL;
		 }
		 found_tag = true;
	}

	/*
	 *	It's not found in the dictionary, so we use
	 *	another method to create the attribute.
	 */
	da = dict_attrbyname(attrname);
	if (!da) {
		vp = pairmake_any(ctx, attrname, value, op);
		if (vp && vps) pairadd(vps, vp);
		return vp;
	}

	/*      Check for a tag in the 'Merit' format of:
	 *      :Tag:Value.  Print an error if we already found
	 *      a tag in the Attribute.
	 */

	if (value && (*value == ':' && da->flags.has_tag)) {
		/* If we already found a tag, this is invalid */
		if(found_tag) {
			fr_strerror_printf("Duplicate tag %s for attribute %s",
				   value, da->name);
			DEBUG("Duplicate tag %s for attribute %s\n",
				   value, da->name);
			return NULL;
		}
		/* Colon found and attribute allows a tag */
		if (value[1] == '*' && value[2] == ':') {
		       /* Wildcard tag for check items */
		       tag = TAG_ANY;
		       value += 3;
		} else {
		       /* Real tag */
		       tag = strtol(value + 1, &tc, 0);
		       if (tc && *tc==':' && TAG_VALID_ZERO(tag))
			    value = tc + 1;
		       else tag = 0;
		}
	}

	vp = pairalloc(ctx, da);
	if (!vp) return NULL;
	vp->op = (op == 0) ? T_OP_EQ : op;
	vp->tag = tag;

	switch (vp->op) {
	case T_OP_CMP_TRUE:
	case T_OP_CMP_FALSE:
		vp->vp_strvalue = NULL;
		vp->vp_length = 0;
		value = NULL;	/* ignore it! */
		break;

		/*
		 *	Regular expression comparison of integer attributes
		 *	does a STRING comparison of the names of their
		 *	integer attributes.
		 */
	case T_OP_REG_EQ:	/* =~ */
	case T_OP_REG_NE:	/* !~ */
	{
#ifndef HAVE_REGEX
		fr_strerror_printf("Regular expressions are not supported");
		return NULL;
#else
		ssize_t slen;
		regex_t *preg;

		/*
		 *	Someone else will fill in the value.
		 */
		if (!value) break;

		talloc_free(vp);

		slen = regex_compile(ctx, &preg, value, strlen(value), false, false, false, true);
		if (slen <= 0) {
			fr_strerror_printf("Error at offset %zu compiling regex for %s: %s", -slen,
					   attribute, fr_strerror());
			return NULL;
		}
		talloc_free(preg);

		vp = pairmake(ctx, NULL, attribute, NULL, op);
		if (!vp) return NULL;

		if (pairmark_xlat(vp, value) < 0) {
			talloc_free(vp);
			return NULL;
		}

		value = NULL;	/* ignore it */
		break;
#endif
	}
	default:
		break;
	}

	/*
	 *	FIXME: if (strcasecmp(attribute, vp->da->name) != 0)
	 *	then the user MAY have typed in the attribute name
	 *	as Vendor-%d-Attr-%d, and the value MAY be octets.
	 *
	 *	We probably want to fix pairparsevalue to accept
	 *	octets as values for any attribute.
	 */
	if (value && (pairparsevalue(vp, value, -1) < 0)) {
		talloc_free(vp);
		return NULL;
	}

	if (vps) pairadd(vps, vp);
	return vp;
}

/** Mark a valuepair for xlat expansion
 *
 * Copies xlat source (unprocessed) string to valuepair value, and sets value type.
 *
 * @param vp to mark for expansion.
 * @param value to expand.
 * @return
 *	- 0 if marking succeeded.
 *	- -1 if #VALUE_PAIR already had a value, or OOM.
 */
int pairmark_xlat(VALUE_PAIR *vp, char const *value)
{
	char *raw;

	/*
	 *	valuepair should not already have a value.
	 */
	if (vp->type != VT_NONE) {
		return -1;
	}

	raw = talloc_typed_strdup(vp, value);
	if (!raw) {
		return -1;
	}

	vp->type = VT_XLAT;
	vp->xlat = raw;
	vp->vp_length = 0;

	return 0;
}


/** Read a single valuepair from a buffer, and advance the pointer
 *
 *  Returns T_EOL if end of line was encountered.
 *
 * @param[in,out] ptr to read from and update.
 * @param[out] raw The struct to write the raw VALUE_PAIR to.
 * @return the last token read.
 */
FR_TOKEN pairread(char const **ptr, VALUE_PAIR_RAW *raw)
{
	char const	*p;
	char *q;
	FR_TOKEN	ret = T_INVALID, next, quote;
	char		buf[8];

	if (!ptr || !*ptr || !raw) {
		fr_strerror_printf("Invalid arguments");
		return T_INVALID;
	}

	/*
	 *	Skip leading spaces
	 */
	p = *ptr;
	while ((*p == ' ') || (*p == '\t')) p++;

	if (!*p) {
		fr_strerror_printf("No token read where we expected "
				   "an attribute name");
		return T_INVALID;
	}

	if (*p == '#') return T_HASH;

	/*
	 *	Try to get the attribute name.
	 */
	q = raw->l_opand;
	*q = '\0';
	while (*p) {
		uint8_t const *t = (uint8_t const *) p;

		if (q >= (raw->l_opand + sizeof(raw->l_opand))) {
		too_long:
			fr_strerror_printf("Attribute name too long");
			return T_INVALID;
		}

		/*
		 *	This is arguably easier than trying to figure
		 *	out which operators come after the attribute
		 *	name.  Yes, our "lexer" is bad.
		 */
		if (!dict_attr_allowed_chars[(unsigned int) *t]) {
			break;
		}

		/*
		 *	Attribute:=value is NOT
		 *
		 *	Attribute:
		 *	=
		 *	value
		 */
		if ((*p == ':') && (!isdigit((int) p[1]))) {
			break;
		}

		*(q++) = *(p++);
	}

	/*
	 *	Haven't found any valid characters in the name.
	 */
	if (!*raw->l_opand) {
		fr_strerror_printf("Invalid attribute name");
		return T_INVALID;
	}

	/*
	 *	Look for tag (:#).  This is different from :=, which
	 *	is an operator.
	 */
	if ((*p == ':') && (isdigit((int) p[1]))) {
		if (q >= (raw->l_opand + sizeof(raw->l_opand))) {
			goto too_long;
		}
		*(q++) = *(p++);

		while (isdigit((int) *p)) {
			if (q >= (raw->l_opand + sizeof(raw->l_opand))) {
				goto too_long;
			}
			*(q++) = *(p++);
		}
	}

	*q = '\0';
	*ptr = p;

	/* Now we should have an operator here. */
	raw->op = gettoken(ptr, buf, sizeof(buf), false);
	if (raw->op  < T_EQSTART || raw->op  > T_EQEND) {
		fr_strerror_printf("Expecting operator");

		return T_INVALID;
	}

	/*
	 *	Read value.  Note that empty string values are allowed
	 */
	quote = gettoken(ptr, raw->r_opand, sizeof(raw->r_opand), false);
	if (quote == T_EOL) {
		fr_strerror_printf("Failed to get value");

		return T_INVALID;
	}

	/*
	 *	Peek at the next token. Must be T_EOL, T_COMMA, or T_HASH
	 */
	p = *ptr;

	next = gettoken(&p, buf, sizeof(buf), false);
	switch (next) {
	case T_HASH:
		next = T_EOL;
		break;

	case T_EOL:
		break;

	case T_COMMA:
		*ptr = p;
		break;

	default:
		fr_strerror_printf("Expected end of line or comma");
		return T_INVALID;
	}
	ret = next;

	switch (quote) {
	/*
	 *	Perhaps do xlat's
	 */
	case T_DOUBLE_QUOTED_STRING:
		/*
		 *	Only report as double quoted if it contained valid
		 *	a valid xlat expansion.
		 */
		p = strchr(raw->r_opand, '%');
		if (p && (p[1] == '{')) {
			raw->quote = quote;
		} else {
			raw->quote = T_SINGLE_QUOTED_STRING;
		}

		break;
	default:
		raw->quote = quote;

		break;
	}

	return ret;
}

/** Read one line of attribute/value pairs into a list.
 *
 * The line may specify multiple attributes separated by commas.
 *
 * @note If the function returns #T_INVALID, an error has occurred and
 * @note the valuepair list should probably be freed.
 *
 * @param ctx for talloc
 * @param buffer to read valuepairs from.
 * @param list where the parsed VALUE_PAIRs will be appended.
 * @return the last token parsed, or #T_INVALID
 */
FR_TOKEN userparse(TALLOC_CTX *ctx, char const *buffer, VALUE_PAIR **list)
{
	VALUE_PAIR	*vp, *head, **tail;
	char const	*p;
	FR_TOKEN	last_token = T_INVALID;
	VALUE_PAIR_RAW	raw;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0) {
		return T_EOL;
	}

	head = NULL;
	tail = &head;

	p = buffer;
	do {
		raw.l_opand[0] = '\0';
		raw.r_opand[0] = '\0';

		last_token = pairread(&p, &raw);

		/*
		 *	JUST a hash.  Don't try to create a VP.
		 *	Let the caller determine if an empty list is OK.
		 */
		if (last_token == T_HASH) {
			last_token = T_EOL;
			break;
		}
		if (last_token == T_INVALID) break;

		if (raw.quote == T_DOUBLE_QUOTED_STRING) {
			vp = pairmake(ctx, NULL, raw.l_opand, NULL, raw.op);
			if (!vp) {
				last_token = T_INVALID;
				break;
			}
			if (pairmark_xlat(vp, raw.r_opand) < 0) {
				talloc_free(vp);
				last_token = T_INVALID;
				break;
			}
		} else {
			vp = pairmake(ctx, NULL, raw.l_opand, raw.r_opand, raw.op);
			if (!vp) {
				last_token = T_INVALID;
				break;
			}
		}

		*tail = vp;
		tail = &((*tail)->next);
	} while (*p && (last_token == T_COMMA));

	if (last_token == T_INVALID) {
		pairfree(&head);
	} else {
		pairadd(list, head);
	}

	/*
	 *	And return the last token which we read.
	 */
	return last_token;
}

/*
 *	Read valuepairs from the fp up to End-Of-File.
 */
int readvp2(TALLOC_CTX *ctx, VALUE_PAIR **out, FILE *fp, bool *pfiledone)
{
	char buf[8192];
	FR_TOKEN last_token = T_EOL;

	vp_cursor_t cursor;

	VALUE_PAIR *vp = NULL;
	fr_cursor_init(&cursor, out);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP
		 */
		if (buf[0] == '\n') {
			if (vp) {
				*pfiledone = false;
				return 0;
			}
			continue;
		}

		/*
		 *	Comments get ignored
		 */
		if (buf[0] == '#') continue;

		/*
		 *	Read all of the attributes on the current line.
		 */
		vp = NULL;
		last_token = userparse(ctx, buf, &vp);
		if (!vp) {
			if (last_token != T_EOL) goto error;
			break;
		}

		fr_cursor_merge(&cursor, vp);
		buf[0] = '\0';
	}
	*pfiledone = true;

	return 0;

error:
	*pfiledone = false;
	vp = fr_cursor_first(&cursor);
	if (vp) pairfree(&vp);

	return -1;
}

/** Compare two pairs, using the operator from "a"
 *
 *	i.e. given two attributes, it does:
 *
 *	(b->data) (a->operator) (a->data)
 *
 *	e.g. "foo" != "bar"
 *
 * @param[in] a the first attribute
 * @param[in] b the second attribute
 * @return
 *	- 1 if true.
 *	- 0 if false.
 *	- -1 on failure.
 */
int paircmp(VALUE_PAIR *a, VALUE_PAIR *b)
{
	if (!a) return -1;

	VERIFY_VP(a);
	if (b) VERIFY_VP(b);

	switch (a->op) {
	case T_OP_CMP_TRUE:
		return (b != NULL);

	case T_OP_CMP_FALSE:
		return (b == NULL);

		/*
		 *	a is a regex, compile it, print b to a string,
		 *	and then do string comparisons.
		 */
	case T_OP_REG_EQ:
	case T_OP_REG_NE:
#ifndef HAVE_REGEX
		return -1;
#else
		if (!b) return false;

		{
			ssize_t	slen;
			regex_t	*preg;
			char	*value;

			if (!fr_assert(a->da->type == PW_TYPE_STRING)) return -1;

			slen = regex_compile(NULL, &preg, a->vp_strvalue, a->vp_length, false, false, false, true);
			if (slen <= 0) {
				fr_strerror_printf("Error at offset %zu compiling regex for %s: %s",
						   -slen, a->da->name, fr_strerror());
				return -1;
			}
			value = vp_aprints_value(NULL, b, '\0');
			if (!value) {
				talloc_free(preg);
				return -1;
			}

			/*
			 *	Don't care about substring matches, oh well...
			 */
			slen = regex_exec(preg, value, talloc_array_length(value) - 1, NULL, NULL);
			talloc_free(preg);
			talloc_free(value);

			if (slen < 0) return -1;
			if (a->op == T_OP_REG_EQ) return (int)slen;
			return !slen;
		}
#endif

	default:		/* we're OK */
		if (!b) return false;
		break;
	}

	return paircmp_op(a->op, b, a);
}

/** Determine equality of two lists
 *
 * This is useful for comparing lists of attributes inserted into a binary tree.
 *
 * @param a first list of #VALUE_PAIR.
 * @param b second list of #VALUE_PAIR.
 * @return
 *	- -1 if a < b.
 *	- 0 if the two lists are equal.
 *	- 1 if a > b.
 *	- -2 on error.
 */
int pairlistcmp(VALUE_PAIR *a, VALUE_PAIR *b)
{
	vp_cursor_t a_cursor, b_cursor;
	VALUE_PAIR *a_p, *b_p;
	int ret;

	for (a_p = fr_cursor_init(&a_cursor, &a), b_p = fr_cursor_init(&b_cursor, &b);
	     a_p && b_p;
	     a_p = fr_cursor_next(&a_cursor), b_p = fr_cursor_next(&b_cursor)) {
		/* Same VP, no point doing expensive checks */
		if (a_p == b_p) {
			continue;
		}

		if (a_p->da < b_p->da) {
			return -1;
		}
		if (a_p->da > b_p->da) {
			return 1;
		}

		if (a_p->tag < b_p->tag) {
			return -1;
		}
		if (a_p->tag > b_p->tag) {
			return 1;
		}

		ret = value_data_cmp(a_p->da->type, &a_p->data, a_p->vp_length,
				     b_p->da->type, &b_p->data, b_p->vp_length);
		if (ret != 0) {
			fr_assert(ret >= -1); 	/* Comparison error */
			return ret;
		}
	}

	if (!a_p && !b_p) {
		return 0;
	}

	if (!a_p) {
		return -1;
	}

	/* if(!b_p) */
	return 1;
}

/** Set the type of the VALUE_PAIR value buffer to match it's DICT_ATTR
 *
 * @param vp to fixup.
 */
static void pairtypeset(VALUE_PAIR *vp)
{
	if (!vp->data.ptr) return;

	switch (vp->da->type) {
	case PW_TYPE_OCTETS:
	case PW_TYPE_TLV:
		talloc_set_type(vp->data.ptr, uint8_t);
		return;

	case PW_TYPE_STRING:
		talloc_set_type(vp->data.ptr, char);
		return;

	default:
		return;
	}
}

/** Copy data into an "octets" data type.
 *
 * @param[in,out] vp to update
 * @param[in] src data to copy
 * @param[in] size of the data, may be 0 in which case previous value will be freed.
 */
void pairmemcpy(VALUE_PAIR *vp, uint8_t const *src, size_t size)
{
	uint8_t *p = NULL, *q;

	VERIFY_VP(vp);

	if (size > 0) {
		p = talloc_memdup(vp, src, size);
		if (!p) return;
		talloc_set_type(p, uint8_t);
	}

	memcpy(&q, &vp->vp_octets, sizeof(q));
	TALLOC_FREE(q);

	vp->vp_octets = p;
	vp->vp_length = size;

	if (size > 0) pairtypeset(vp);
}

/** Reparent an allocated octet buffer to a VALUE_PAIR
 *
 * @param[in,out] vp to update
 * @param[in] src buffer to steal.
 */
void pairmemsteal(VALUE_PAIR *vp, uint8_t const *src)
{
	uint8_t *q;

	VERIFY_VP(vp);

	memcpy(&q, &vp->vp_octets, sizeof(q));
	talloc_free(q);

	vp->vp_octets = talloc_steal(vp, src);
	vp->type = VT_DATA;
	vp->vp_length = talloc_array_length(vp->vp_strvalue);
	pairtypeset(vp);
}

/** Reparent an allocated char buffer to a VALUE_PAIR
 *
 * @param[in,out] vp to update
 * @param[in] src buffer to steal.
 */
void pairstrsteal(VALUE_PAIR *vp, char const *src)
{
	uint8_t *q;

	VERIFY_VP(vp);

	memcpy(&q, &vp->vp_octets, sizeof(q));
	talloc_free(q);

	vp->vp_strvalue = talloc_steal(vp, src);
	vp->type = VT_DATA;
	vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
	pairtypeset(vp);
}

/** Copy data into an "string" data type.
 *
 * @param[in,out] vp to update
 * @param[in] src data to copy
 */
void pairstrcpy(VALUE_PAIR *vp, char const *src)
{
	char *p, *q;

	VERIFY_VP(vp);

	p = talloc_strdup(vp, src);

	if (!p) return;

	memcpy(&q, &vp->vp_strvalue, sizeof(q));
	talloc_free(q);

	vp->vp_strvalue = p;
	vp->type = VT_DATA;
	vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
	pairtypeset(vp);
}

/** Copy data into an "string" data type.
 *
 * @note unlike the original strncpy, this function does not stop
 *	if it finds \0 bytes embedded in the string.
 *
 * @param[in,out] vp to update.
 * @param[in] src data to copy.
 * @param[in] len of data to copy.
 */
void pairbstrncpy(VALUE_PAIR *vp, char const *src, size_t len)
{
	char *p, *q;

	VERIFY_VP(vp);

	p = talloc_array(vp, char, len + 1);
	if (!p) return;

	memcpy(p, src, len);	/* embdedded \0 safe */
	p[len] = '\0';

	memcpy(&q, &vp->vp_strvalue, sizeof(q));
	talloc_free(q);

	vp->vp_strvalue = p;
	vp->type = VT_DATA;
	vp->vp_length = len;
	pairtypeset(vp);
}

/** Print data into an "string" data type.
 *
 * @param[in,out] vp to update
 * @param[in] fmt the format string
 */
void pairsprintf(VALUE_PAIR *vp, char const *fmt, ...)
{
	va_list ap;
	char *p, *q;

	VERIFY_VP(vp);

	va_start(ap, fmt);
	p = talloc_vasprintf(vp, fmt, ap);
	va_end(ap);

	if (!p) return;

	memcpy(&q, &vp->vp_strvalue, sizeof(q));
	talloc_free(q);

	vp->vp_strvalue = p;
	vp->type = VT_DATA;

	vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
	pairtypeset(vp);
}

#ifdef WITH_VERIFY_PTR
/*
 *	Verify a VALUE_PAIR
 */
inline void fr_pair_verify_vp(char const *file, int line, VALUE_PAIR const *vp)
{
	if (!vp) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR pointer was NULL", file, line);
		fr_assert(0);
		fr_exit_now(1);
	}

	(void) talloc_get_type_abort(vp, VALUE_PAIR);

	if (!vp->da) {
		FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR da pointer was NULL", file, line);
		fr_assert(0);
		fr_exit_now(1);
	}

	if (vp->data.ptr) switch (vp->da->type) {
	case PW_TYPE_OCTETS:
	case PW_TYPE_TLV:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->data.ptr, uint8_t)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" data buffer type should be "
				     "uint8_t but is %s\n", file, line, vp->da->name, talloc_get_name(vp->data.ptr));
			(void) talloc_get_type_abort(vp->data.ptr, uint8_t);
		}

		len = talloc_array_length(vp->vp_octets);
		if (vp->vp_length > len) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" length %zu is greater than "
				     "uint8_t data buffer length %zu\n", file, line, vp->da->name, vp->vp_length, len);
			fr_assert(0);
			fr_exit_now(1);
		}

		parent = talloc_parent(vp->data.ptr);
		if (parent != vp) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer is not "
				     "parented by VALUE_PAIR %p, instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     vp, parent, parent ? talloc_get_name(parent) : "NULL");
			fr_assert(0);
			fr_exit_now(1);
		}
	}
		break;

	case PW_TYPE_STRING:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->data.ptr, char)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" data buffer type should be "
				     "char but is %s\n", file, line, vp->da->name, talloc_get_name(vp->data.ptr));
			(void) talloc_get_type_abort(vp->data.ptr, char);
		}

		len = (talloc_array_length(vp->vp_strvalue) - 1);
		if (vp->vp_length > len) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" length %zu is greater than "
				     "char buffer length %zu\n", file, line, vp->da->name, vp->vp_length, len);
			fr_assert(0);
			fr_exit_now(1);
		}

		if (vp->vp_strvalue[vp->vp_length] != '\0') {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer not \\0 "
				     "terminated\n", file, line, vp->da->name);
			fr_assert(0);
			fr_exit_now(1);
		}

		parent = talloc_parent(vp->data.ptr);
		if (parent != vp) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR \"%s\" char buffer is not "
				     "parented by VALUE_PAIR %p, instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     vp, parent, parent ? talloc_get_name(parent) : "NULL");
			fr_assert(0);
			fr_exit_now(1);
		}
	}
		break;

	default:
		break;
	}

	if (vp->da->flags.is_unknown) {
		(void) talloc_get_type_abort(vp->da, DICT_ATTR);
	} else {
		DICT_ATTR const *da;

		/*
		 *	Attribute may be present with multiple names
		 */
		da = dict_attrbyname(vp->da->name);
		if (!da) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR attribute %p \"%s\" (%s) "
				     "not found in global dictionary",
				     file, line, vp->da, vp->da->name,
				     fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"));
			fr_assert(0);
			fr_exit_now(1);
		}

		if (da->type == PW_TYPE_COMBO_IP_ADDR) {
			da = dict_attrbytype(vp->da->attr, vp->da->vendor, vp->da->type);
			if (!da) {
				FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR attribute %p \"%s\" "
					     "variant (%s) not found in global dictionary",
					     file, line, vp->da, vp->da->name,
					     fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"));
				fr_assert(0);
				fr_exit_now(1);
			}
		}


		if (da != vp->da) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: VALUE_PAIR "
				     "dictionary pointer %p \"%s\" (%s) "
				     "and global dictionary pointer %p \"%s\" (%s) differ",
				     file, line, vp->da, vp->da->name,
				     fr_int2str(dict_attr_types, vp->da->type, "<INVALID>"),
				     da, da->name, fr_int2str(dict_attr_types, da->type, "<INVALID>"));
			fr_assert(0);
			fr_exit_now(1);
		}
	}
}

/*
 *	Verify a pair list
 */
void fr_pair_verify_list(char const *file, int line, TALLOC_CTX *expected, VALUE_PAIR *vps)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	TALLOC_CTX *parent;

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VERIFY_VP(vp);

		parent = talloc_parent(vp);
		if (expected && (parent != expected)) {
			FR_FAULT_LOG("CONSISTENCY CHECK FAILED %s[%u]: Expected VALUE_PAIR \"%s\" to be parented "
				     "by %p (%s), instead parented by %p (%s)\n",
				     file, line, vp->da->name,
				     expected, talloc_get_name(expected),
				     parent, parent ? talloc_get_name(parent) : "NULL");

			fr_log_talloc_report(expected);
			if (parent) fr_log_talloc_report(parent);

			fr_assert(0);
			fr_exit_now(1);
		}

	}
}
#endif
