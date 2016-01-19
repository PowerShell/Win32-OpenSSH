
#ifndef _OPENSSL_WRAP_H
#define _OPENSSL_WRAP_H

struct sshdh;
struct sshbn;
struct sshbuf;
struct ssh;

struct sshdh *sshdh_new(void);
void sshdh_free(struct sshdh *dh);
struct sshbn *sshdh_pubkey(struct sshdh *dh);
struct sshbn *sshdh_p(struct sshdh *dh);
struct sshbn *sshdh_g(struct sshdh *dh);
void sshdh_dump(struct sshdh *dh);
size_t sshdh_shared_key_size(struct sshdh *dh);
int sshdh_compute_key(struct sshdh *dh, struct sshbn *pubkey,
struct sshbn **shared_secretp);
int sshdh_generate(struct sshdh *dh, size_t len);
int sshdh_new_group_hex(const char *gen, const char *modulus,
struct sshdh **dhp);
struct sshdh *sshdh_new_group(struct sshbn *gen, struct sshbn *modulus);

struct sshbn *sshbn_new(void);
void sshbn_free(struct sshbn *bn);
int sshbn_from(const void *d, size_t l, struct sshbn **retp);
int sshbn_from_hex(const char *hex, struct sshbn **retp);
size_t sshbn_bits(const struct sshbn *bn);
const struct sshbn *sshbn_value_0(void);
const struct sshbn *sshbn_value_1(void);
int sshbn_cmp(const struct sshbn *a, const struct sshbn *b);
int sshbn_sub(struct sshbn *r, const struct sshbn *a, const struct sshbn *b);
int sshbn_is_bit_set(const struct sshbn *bn, size_t i);
int sshbn_to(const struct sshbn *a, unsigned char *to);
size_t sshbn_bytes(const struct sshbn *bn);

/* XXX move to sshbuf.h; rename s/_wrap$// */
int sshbuf_get_bignum2_wrap(struct sshbuf *buf, struct sshbn *bn);
int sshbuf_get_bignum1_wrap(struct sshbuf *buf, struct sshbn *bn);
int sshbuf_put_bignum2_wrap(struct sshbuf *buf, const struct sshbn *bn);
int sshbuf_put_bignum1_wrap(struct sshbuf *buf, const struct sshbn *bn);
int sshpkt_get_bignum2_wrap(struct ssh *ssh, struct sshbn *bn);
int sshpkt_put_bignum2_wrap(struct ssh *ssh, const struct sshbn *bn);

/* bridge to unwrapped OpenSSL APIs; XXX remove later */
struct sshbn *sshbn_from_bignum(BIGNUM *bn);
BIGNUM *sshbn_bignum(struct sshbn *bn);
DH *sshdh_dh(struct sshdh *dh);


#endif /* _OPENSSL_WRAP_H */