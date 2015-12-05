//Initializers
//openSSL 
struct sshdh *sshdh_openssl_new(void);
//ms_cng
struct sshdh *sshdh_ms_cng_new(void);

//need to think about this one
struct sshdh *sshdh_new_group(struct sshbn *gen, struct sshbn *modulus);

struct sshdh{
    //Interface
    void (*sshdh_free)(struct sshdh *dh);
    struct sshbn *(*sshdh_pubkey)(struct sshdh *dh);
    struct sshbn *(*sshdh_p)(struct sshdh *dh);
    struct sshbn *(*sshdh_g)(struct sshdh *dh);
    void (*sshdh_dump)(struct sshdh *dh);
    size_t (*sshdh_shared_key_size)(struct sshdh *dh);
    int (*sshdh_compute_key)(struct sshdh *dh, struct sshbn *pubkey, struct sshbn **shared_secretp);
    int (*sshdh_generate)(struct sshdh *dh, size_t len);
    int (*sshdh_new_group_hex)(const char *gen, const char *modulus, struct sshdh **dhp);
    //Initializer of sshbn done in the context of a sshdh. 
    struct sshbn *(*sshbn_new)();
};

struct sshbn {
    void (*sshbn_free)(struct sshbn *bn);
    int (*sshbn_from)(const void *d, size_t l, struct sshbn **retp);
    int (*sshbn_from_hex)(const char *hex, struct sshbn **retp);
    size_t (*sshbn_bits)(const struct sshbn *bn);
    const struct sshbn *(*sshbn_value_0)(void);
    const struct sshbn *(*sshbn_value_1)(void);
    int (*sshbn_is_bit_set)(const struct sshbn *bn, size_t i);

    //TODO: enforce that multiple sshbn instances involved are from the same implementation. 
    int sshbn_cmp(const struct sshbn *b);
    int sshbn_sub(struct sshbn *r, const struct sshbn *b);
};