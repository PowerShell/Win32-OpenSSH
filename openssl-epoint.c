/*
* Copyright (c) 2015 Damien Miller <djm@mindrot.org>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <includes.h>


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>


#include <openssl/bn.h>
#include <openssl/ec.h>


#include "sshbuf.h"
#include "packet.h"
#include "ssherr.h"
#include "crypto-wrap.h"

struct sshepoint {
	EC_POINT *pt;
	EC_GROUP *gp;
};

struct sshecurve {
	EC_GROUP *gp;
};


struct sshepoint *
	sshepoint_new(void)
{
	return malloc(sizeof(struct sshepoint));
}

void
sshepoint_free(struct sshepoint *pt)
{
	if (pt != NULL) {
		if (pt->pt != NULL)
			EC_POINT_free(pt->pt);
		if (pt->gp != NULL)
			EC_GROUP_free(pt->gp);
		explicit_bzero(pt, sizeof(*pt));
		free(pt);
	}
}


int sshepoint_from(struct sshbn * x, struct sshbn * y, struct sshecurve * curve, struct sshepoint **retp)
{
	struct sshepoint *ret = NULL;


	*retp = NULL;
	if ((ret = sshepoint_new()) == NULL) 
	{
		return SSH_ERR_ALLOC_FAIL;
	}
	if ((ret->pt = EC_POINT_new(curve->gp)) == NULL)
	{
		sshepoint_free(ret);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	ret->gp = curve->gp;
	if (EC_POINT_set_affine_corrdinates_GFp(curve->gp, ret->pt, x, y)) {
		sshepoint_free(ret);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*retp = ret;
	return 0;
}
int sshepoint_to(struct sshepoint * pt, struct sshbn  **retx, struct sshbn **rety, struct sshecurve ** retcurve)
{
	struct sshbn * x = NULL;
	struct sshbn * y = NULL;
	struct sshecurve * curve = NULL;

	if (((x = sshbn_new()) == NULL) ||
		((y = sshbn_new()) == NULL) ||
		((curve = sshecurve_new()) == NULL))
	{
		sshbn_free(x);
		sshbn_free(y);
		sshecurve_free(curve);
		return SSH_ERR_ALLOC_FAIL;
	}

	curve->gp = pt->gp;
	if (EC_POINT_get_affine_coordinates_GFp(pt->gp, pt->pt, sshbn_bignum(x), sshbn_bignum(y), NULL))
	{
		sshecurve_free(curve);
		sshbn_free(x);
		sshbn_free(y);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	*retcurve = curve;
	*retx = x;
	*rety = y;

	return 0;
}

struct sshecurve * sshecurve_new(void)
{
	struct sshecurve * curve = NULL;

	curve = (struct sshecurve *)malloc(sizeof(struct sshecurve));
	memset(curve, 0, sizeof(struct sshecurve));

	return curve;
}

void sshecurve_free(struct sshecurve * curve)
{
	if (curve != NULL) {
		if (curve->gp != NULL)
			EC_GROUP_free(curve->gp);
		explicit_bzero(curve, sizeof(*curve));
		free(curve);
	}
}

struct sshecurve * sshecurve_new_curve(int nid)
{
	struct sshecurve * ret;

	if ((ret = sshecurve_new()) == NULL)
		return NULL;
	ret->gp = EC_GROUP_new_by_curve_name(nid);

	return ret;


}