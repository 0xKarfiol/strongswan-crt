/*
 * Copyright (C) 2026 secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "test_suite.h"

#include <crypto/crypto_factory.h>

static struct {
	key_exchange_method_t method;
	size_t pubkey_len;
} zero_pubkeys[] = {
	{ CURVE_25519, 32 },
	{ CURVE_448, 56 },
};

/**
 * Check if wolfSSL is the selected provider for the given key exchange method.
 */
static bool uses_wolfssl(key_exchange_method_t method)
{
	enumerator_t *enumerator;
	const char *plugin;
	key_exchange_method_t current;
	bool found = FALSE;

	enumerator = lib->crypto->create_ke_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &current, &plugin))
	{
		if (current == method)
		{
			found = streq(plugin, "wolfssl");
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

START_TEST(test_zero_shared_secret_rejected)
{
	key_exchange_t *ke;
	chunk_t pub = chunk_empty, secret = chunk_empty;
	bool ok;

	if (!uses_wolfssl(zero_pubkeys[_i].method))
	{
		return;
	}

	ke = lib->crypto->create_ke(lib->crypto, zero_pubkeys[_i].method);
	ck_assert_msg(ke, "creating %N via wolfssl failed",
				  key_exchange_method_names, zero_pubkeys[_i].method);

	pub = chunk_alloc(zero_pubkeys[_i].pubkey_len);
	memset(pub.ptr, 0, pub.len);

	ok = ke->set_public_key(ke, pub);
	if (ok)
	{
		ok = !ke->get_shared_secret(ke, &secret);
	}

	chunk_free(&pub);
	chunk_clear(&secret);
	ke->destroy(ke);

	ck_assert_msg(ok, "%N accepted an all-zero peer public key",
				  key_exchange_method_names, zero_pubkeys[_i].method);
}
END_TEST

Suite *wolfssl_x_diffie_hellman_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("wolfssl-x-diffie-hellman");

	tc = tcase_create("all-zero-shared-secret");
	tcase_add_loop_test(tc, test_zero_shared_secret_rejected, 0,
					 countof(zero_pubkeys));
	suite_add_tcase(s, tc);

	return s;
}
