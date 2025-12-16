#include <format>
#include <iostream>
#include <print>

#include <gmpxx.h>
#include <unordered_map>
#include <utility>

auto calculate_h_inv_gx(const mpz_class &h, const mpz_class &g, const mpz_class &x1, const mpz_class &p) -> mpz_class {
    mpz_class gx;
    mpz_powm(gx.get_mpz_t(), g.get_mpz_t(), x1.get_mpz_t(), p.get_mpz_t());

    mpz_class inv_gx;
    if (mpz_invert(inv_gx.get_mpz_t(), gx.get_mpz_t(), p.get_mpz_t()) == 0) {
        throw std::runtime_error("g^x has no inverse modulo p");
    }

    mpz_class result = (h * inv_gx) % p;
    if (result < 0)
        result += p;

    return result;
}

// WARNING: USES INTERNALS, MAY BE NOT PORTABLE.
struct MpzRobustHash {
    std::size_t operator()(const mpz_class &n) const noexcept {
        const mp_limb_t *limbs = n.get_mpz_t()->_mp_d;
        // abs() is needed because _mp_size is negative for negative numbers
        std::size_t count = std::abs(n.get_mpz_t()->_mp_size);

        // Initialize with a seed (arbitrary large prime)
        std::size_t h = 0xc70f6907UL;

        for (std::size_t i = 0; i < count; ++i) {
            // Mix the limb into the hash
            h ^= std::hash<mp_limb_t>{}(limbs[i]);
            // A strong mixer (MurmurHash3-style finalizer constant)
            h *= 0xff51afd7ed558ccdUL;
            // Rotate bits to spread entropy
            h = (h << 13) | (h >> 51);
        }

        return h;
    }
};

auto generate_hash_table(const mpz_class &h, const mpz_class &g, const mpz_class &p,
                         const mpz_class &B) -> std::unordered_map<mpz_class, mpz_class, MpzRobustHash> {
    std::unordered_map<mpz_class, mpz_class, MpzRobustHash> hash_table;

    hash_table.reserve(B.get_ui());
    for (mpz_class x1 = 0; x1 < B; ++x1) {
        mpz_class key = calculate_h_inv_gx(h, g, x1, p);
        hash_table.emplace(std::move(key), x1);
    }

    return hash_table;
}

auto meet_in_the_middle_attack(std::unordered_map<mpz_class, mpz_class, MpzRobustHash> hash_table, const mpz_class &g,
                               const mpz_class &p, const mpz_class &B) -> mpz_class {
    mpz_class gB;
    mpz_powm(gB.get_mpz_t(), g.get_mpz_t(), B.get_mpz_t(), p.get_mpz_t());

    for (mpz_class x0 = 0; x0 < B; ++x0) {
        mpz_class gB_x0;
        mpz_powm(gB_x0.get_mpz_t(), gB.get_mpz_t(), x0.get_mpz_t(), p.get_mpz_t());

        auto it = hash_table.find(gB_x0);
        if (it != hash_table.end()) {
            mpz_class x1 = it->second;
            mpz_class x = x0 * B + x1;

            return x;
        }
    }

    throw std::runtime_error("No solution found");
}

int main(int, char *[]) {
    const mpz_class B = mpz_class(1 << 20);

    const mpz_class p = mpz_class("134078079299425970995740249982058461274793658205923933"
                                  "77723561443721764030073546976801874298166903427690031"
                                  "858186486050853753882811946569946433649006084171",
                                  10);

    const mpz_class g = mpz_class("11717829880366207009516117596335367088558084999998952205"
                                  "59997945906392949973658374667057217647146031292859482967"
                                  "5428279466566527115212748467589894601965568",
                                  10);

    const mpz_class h = mpz_class("323947510405045044356526437872806578864909752095244"
                                  "952783479245297198197614329255807385693795855318053"
                                  "2878928001494706097394108577585732452307673444020333",
                                  10);

    auto hash_table = generate_hash_table(h, g, p, B);

    auto x = meet_in_the_middle_attack(std::move(hash_table), g, p, B);

    println("Found x: {}", x.get_str()); // 375374217830

    return 0;
}
