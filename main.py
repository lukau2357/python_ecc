import streamlit as st
import secrets
import io
import hashlib

from src.miller_rabin import miller_rabin_generator_wrapper
from src.ecc import double_and_add, ecc_add
from PIL import Image

ECC_STANDARDS = {
    "secp256k1": {
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "a": 0,
        "b": 7,
        "G": (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
        "order_G": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        "url": "https://en.bitcoin.it/wiki/Secp256k1",
        "Trivia": "Used for signing Bitcoin transactions"
    },

    "brainpoolP256r1": {
        "p": 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
        "a": 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9,
        "b": 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6,
        "G": (0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262, 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997),
        "order_G": 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
        "url": "https://neuromancer.sk/std/brainpool/brainpoolP256r1#"
    },

    "nistp256": {
        "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        "G": (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
        "order_G": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        "url": "https://neuromancer.sk/std/nist/P-256#"
    }
}

for key in ECC_STANDARDS.keys():
    p_string = str(ECC_STANDARDS[key]["p"])
    G_string = str(ECC_STANDARDS[key]["G"])
    a_string = str(ECC_STANDARDS[key]["a"])
    b_string = str(ECC_STANDARDS[key]["b"])
    order_G_string = str(ECC_STANDARDS[key]["order_G"])
    prime_bits = ECC_STANDARDS[key]["p"].bit_length()
    order_G_bits = ECC_STANDARDS[key]["order_G"].bit_length()

    ECC_STANDARDS[key]["p_string"] = p_string
    ECC_STANDARDS[key]["G_string"] = G_string
    ECC_STANDARDS[key]["a_string"] = a_string
    ECC_STANDARDS[key]["b_string"] = b_string
    ECC_STANDARDS[key]["order_G_string"] = order_G_string
    ECC_STANDARDS[key]["p_bits"] = str(prime_bits)
    ECC_STANDARDS[key]["order_G_bits"] = str(order_G_bits)

def d2hex(x):
    h = hex(x)
    return ":".join([h[i : i + 2] for i in range(2, len(h), 2)])

def main():
    def miller_rabin_generator(container):    
        result = miller_rabin_generator_wrapper(st.session_state["prime_bits"], st.session_state["num_trials"], st.session_state["num_processes"], debug = False)
        st.session_state["prime"] = result["prime"]
        st.session_state["worst_case_probability"] = result["worst_case_probability"]
        st.session_state["time_taken_seconds"] = result["time_taken_seconds"]
        st.session_state["iterations"] = result["iterations"]
        container.write(f"""
                 **Found prime**: {st.session_state["prime"]}\n
                 **Worst-case probability of the given number being composite**: {st.session_state["worst_case_probability"]}\n
                 **Number of iterations until the number was found**: {st.session_state["iterations"]}\n
                 **Time spent (not including process creation overhead)**: {st.session_state["time_taken_seconds"]:.4f}s.\n
                 """)
        
    st.set_page_config(page_title = "ECC", layout = "wide")
    st.title("Elliptic Curve Cryptography in Python")        

    st.markdown(r"""
                ## ECC Overview
                First we provide a mathematical overview of ECC. An elliptic curve in $\mathbb{R}^{2}$ is given by the set of all points
                that satisfy the Weirestrass equation:

                $$
                E: Y^2 = X^3 + ax + b, \Delta_E = 4a^3 + 27b^2 \neq 0
                $$

                We will see why the second regularity condition is required soon. Let $P, Q$ be two points from $E$. We define the addition
                of points $P, Q$ as follows: We start by drawing the line L through P and Q. This line L intersects E at three points, namely P, Q, and one other point R. We take
                that point R and reflect it across the x-axis (i.e., we multiply its Y-coordinateby −1) to get a new point R. 
                The point R is called the "sum of P and Q", and we use the notation $R = P \oplus Q$. This procedure can be seen on the figure below:
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/ecc_2.png", caption = "Source: [1]")

    st.markdown(r"""
                As a special case, when $P = Q$, we more or less repeat the same procedure, only in the first step we construct a tangent line to the curve $E$
                in point $P$.
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/ecc_3.png", caption = "Source: [1]")

    st.markdown(r"""
                The regularity condition that we imposed earlier, $\Delta_E = 4a^3 + 27b^2 \neq 0$ is equivalent to the given curve having repeated roots, and in this case
                the derivatives would not be properly defined for these repeated roots, which means that addition would not be properly defined for 
                every point that satisfies the curve equation.
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/ecc_4.png", caption = "Examples of elliptic-like curves with repeated roots.")

    st.markdown(r"""
                Another special case for addition that requires attention is if $P = (x, y), P' = (x, -y)$. If we were to draw a line through $P$ and $P'$,
                there would be no third point from $E$ that would also belong to the given line. A special point is introduced, $\mathcal{O}$, with the property that 
                it is contained in every vertical line in $\mathbb{R}^2$, and thus $P \oplus P' = \mathcal{O}$. We will use the notation $P' = -P$.
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/ecc_6.png", caption = "Adding a point to it's 'inverse'. Source: [1]")

    st.markdown(r"""
                From the previous figure, it is also easy to veirfy that $P \oplus \mathcal{O} = P'$. For a fixed elliptic curve $E$, let $P(E)$ denote all points in $\mathbb{R}^2$
                that satisfy the given curve. The following properties hold:
                * $\forall P \in P(E), P \oplus \mathcal{O} = \mathcal{O} + P = P$ (identity)
                * $\forall P \in P(E), P \oplus (-P) = \mathcal{O}$ (existence of inverse)
                * $\forall P, Q \in P(E), P \oplus Q = Q \oplus p$ (commutativity)
                * $\forall P, Q, R \in P(E), (P \oplus Q) \oplus R = P \oplus (Q \oplus R)$ (associativity)

                Only property that is not so straightforward to prove is associativity, we will not include the proof here - authors of [1] reference papers that
                contain associativity proof. The main point is that $(P(E) \cup \{\mathcal{O}\}, \oplus)$ is an Abelian group. Furthermore, using elementary calculus
                we can derive an exact algorithm to compute $P \oplus Q$:
                """)
    _, image, __ = st.columns(3)
    image.image("./figs/ecc_5.png", caption = "Point addition algorithm: Source: [1]")

    st.markdown(r"""
                ## Elliptic curves over finite fields
                Of particular interest for cryptography are elliptic curves over field of residues modulo $p$, $\mathbb{F_p}$, for a prime number $p$. 
                Let $E$ be an elliptic curve, we define the following:
                $$
                E(\mathbb{F_p}) = \{(x, y) \in \mathbb{F_p}^2 \mid (x, y) \text{ satisfy } E \} \cup \{\mathcal{O}\}
                $$

                For example, consider $E: Y^2 = X^3 + 3X + 8$ and $\mathbb{F_13}$. 
                We can show that $E(\mathbb{F_{13}}) = \{\mathcal{O}, (1, 5), (1, 8), (2, 3), (2, 10), (9, 6), (9, 7), (12, 2), (12, 11)\}$, and thus 
                $|E(\mathbb{F_{13}})| = 9$. 
                
                For a fixed elliptic curve $E$ and field of residues module prime $p$, $\mathbb{F_p}$, the following theorem can be shown:
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/ecc_group.png", caption = "Source: [1]")

    st.markdown(r"""
                Even though this is not important for our use case, the previous theorem can be generalized. 
                If $\mathbb{F} = p^n, n \geq 1$ is a finite field, then $E(\mathbb{F})$ will always be an Abelian group! However, we do not have any guarantees
                that $E(\mathbb{F})$ will be cyclic, and the same applies to $E(\mathbb{F_p})$ as well.


                **Theorem (Hasse)**:
                $$
                |E(\mathbb{F_p})| = p + 1 - t_p, |t_p| \leq 2 \sqrt{p}
                $$
                """)

    st.markdown(r"""
                ## Elliptic Curve Discrete Logarithm Problem - ECDLP
                For a fixed elliptic curve $E$, prime number $p$, $P \in E(\mathbb{F_p})$, $n \in \mathbb{N}$ we have the following:
                $$
                Q = nP = \underbrace{P \oplus \ldots \oplus P}_{n \text{ times}}
                $$

                The elliptic curve discrete logarithm problem - ECDLP boils down to finding $n$ for known values of $Q, P, p, E$. 
                There is no known algorithm that solves the ECDLP problem faster than $O(\sqrt{p})$, 
                while for discrete logarithm in $\mathbb{F_p}$ there is the index calculus ([1]) algorithm that can solve it in 
                sub-exponential time $O(p^\epsilon), \epsilon > 0$. Another appealing property of the group $E(\mathbb{F_p})$ is that cryptographic algorithms
                based on this field can achieve a similar security level as algorithms based in $\mathbb{F_p}$, with a fewer number of bits. For instance, 
                using a prime number of 384 bits in $E(\mathbb{F_p})$ gives roughly the same security as using a prime number of 3072 bits in $\mathbb{F_p}$. [1] 

                When computing $nP$ in practice, we do not actually need to perform $n$ additions - it turns out that we only need $O(logn)$ additions. First, let
                $a \in \mathbb{F_p}, k \geq 0, f(k) \equiv a^k (mod p)$. It's clear that the following recurrence holds:
                $$
                f(k) \equiv \begin{cases} & f(\frac{k}{2})^{2}, k \equiv 0 (mod \text{ } 2) \\
                & f([\frac{k}{2}])^{2} a, k \equiv 1 (mod \text{ } 2) \\
                & 1, k = 0
                \end{cases} (mod p)
                $$

                We can derive a similar algorithm for computing $nP$ in $E(\mathbb{F_p})$, **double-and-add** algorithm:
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/double_and_add.png", caption = "Double-and-add algorithm for elliptic curve point addition. Furthermore, this algorithm can be generalized to any finite group. Source: [1]")

    st.markdown(r"""
    We implemented elliptic curve addition according to previously outlined addition algorithm, as well as the double-and-add algoritm for efficiently computing
    $nP$ in $E(\mathbb{F_p})$.
                
    When it comes to choosing curve $E$, prime $p$ and generator point, this is not so straightforward as for $\mathbb{F_p}$. For $\mathbb{F_p}$ things 
    are relatively easy - we find a large prime number $p$ and compute one generator in $\mathbb{F_p}$. For $E(\mathbb{F_p})$, after choosing the elliptic curve
    and prime number $p$, as we've stated previously we do not have any guarantees that $E(\mathbb{F_p})$ is cyclic, and checking for this condition would be
    very time consuming. Instead, we typically look at a subgroup of $E(\mathbb{F_p})$ generated by some point $G \in E(\mathbb{F_p})$ with a large prime order - 
    this is to ensure that ECDLP remains resistant to Pohlig-Hellman attacks! Typically trusted research institutions publish values for $E, p, G$ as their 
    recommendations. Some popular standards, which you can use for this implementation of ECC are:
    """)

    def write_ecc_standard_options(container):
        options = ECC_STANDARDS[st.session_state["ecc_standard_options"]]
        new_options = {
            "Prime": options["p_string"],
            "Prime number of bits": options["p_bits"],
            "a": options["a_string"],
            "b": options["b_string"],
            "Generator point": options["G_string"],
            "Generator order": options["order_G_string"],
            "Generator order number of bits": options["order_G_bits"],
            "Reference": options["url"],
            }

        if "Trivia" in options.keys():
            new_options["Trivia"] = options["Trivia"]

        container.table(new_options)

    def new_standard():
        if "create_ecdsa_verification_key_clicked" in st.session_state:
            del st.session_state["create_ecdsa_verification_key_clicked"]
        
        if "s" in st.session_state:
            del st.session_state["s"]

        if "V" in st.session_state:
            del st.session_state["V"]
        
        if "s1" in st.session_state:
            del st.session_state["s1"]

        if "s2" in st.session_state:
            del st.session_state["s2"]

    ecc_standard_options = st.selectbox(
        "ECC standard, will be used for algorithms implemented below", tuple(ECC_STANDARDS.keys()), index = 0, key = "ecc_standard_options", accept_new_options = False,
        on_change = new_standard
    )
    ecc_standard_options_container = st.empty()

    write_ecc_standard_options(ecc_standard_options_container)
           
    st.markdown(r"""
                ## ECDH - Elliptic Curve Diffie Hellman
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/ecdh.png", caption = "Pseudocode for ECDH algorithm. Notice that it closely resembles the original DH algorithm. Source: [1]")

    st.markdown(r"""
                This version of ECDH algorithm might seem redundant, because the shared secret ends up being $(n_A n_B)P$, but in practice the communicating
                parties most commonly end up using only one coordinate of $P, x$. This is a valid point, and the algorithm can be slighly modified so as to achieve
                non-redundancy. It turns out that when Alice computes $Q_A = n_A P$, it is sufficient to send only $Q_{A}.x$ to Bob, and the same goes for Bob,
                for him it suffices to send only $Q_{B}.x$ to Alice. Since $Q_{A} \in E(\mathbb{F_p})$, Bob can simply plug-in the $Q_{A}.x$ into the curve equation
                to obtain $(Q_{A}.y)^2 \equiv (Q_{A}.x)^3 + aQ_{A}.x + B (mod \text{ }p)$ and take the square root of $(Q_{A}.y)^2$ from here. There exists a general 
                algorithm, **Tonelli-Shanks ([2])** for computing square roots modulo prime number $p$. However, if $p \equiv 3 (mod \text{ } 4)$, it's very simple 
                to show that if $a$ has a square root modulo $p$, then $b \equiv a^{\frac{p + 1}{4}} (mod \text{ } p)$ is the square root of $a$ modulo $p$. For all
                previous standards (and most other standards), chosen primes satisfy the property $p \equiv 3 (mod \text{ } 4)$ 
                so we will be using this property in our implementation as well.

                At any rate, Bob will end up computing one of $\pm Q_{A}.y$, and similarly Alice will end up computing one of $\pm Q_{B}.y$. If we recall that 
                for $P = (x, y) \in E(\mathbb{F_p}), -P = (x, -y)$, then Bob ends up with $(Q_{A}.x, \pm Q_{A}.y) = \pm Q_{A}$, and Alice ends up with $\pm Q_{B}$.
                Finally when they use their secret keys, they both obtain $(\pm (n_{A} n_{B}) P)$, and since in both cases the $x$ coordinate of the final point stays the same,
                they can both declare $x$ as the shared secret!
                """)

    with st.container(border = True):
        st.header("ECDH simulation")
        st.write(f"**Selected ECC standard**: {st.session_state['ecc_standard_options']}")
        col1, col2, _ = st.columns(3, vertical_alignment = "bottom")

        def generate_ecdh_ephermal_key(key, standard):
            ephermal = secrets.randbelow(ECC_STANDARDS[standard]["order_G"])
            st.session_state[key] = str(ephermal)

        def ecdh_exchange(standard, result_container):
            try:
                alice_ephermal_t = int(st.session_state["alice_ephermal"])
                bob_ephermal_t = int(st.session_state["bob_ephermal"])
            except ValueError:
                result_container.error("Error during parsing of ephermal keys, ensure that passed keys are integers!")
                return
            
            prime = ECC_STANDARDS[standard]["p"]
            G = ECC_STANDARDS[standard]["G"]
            a = ECC_STANDARDS[standard]["a"]
            b = ECC_STANDARDS[standard]["b"]
            order_G = ECC_STANDARDS[standard]["order_G"]

            alice_ephermal_t %= order_G
            bob_ephermal_t %= order_G

            QA = double_and_add(prime, a, alice_ephermal_t, G)
            QB = double_and_add(prime, a, bob_ephermal_t, G)

            QB_x = QB[0]
            QA_x = QA[0]

            QB_y_square = (pow(QB_x, 3, prime) + (a * QB_x) % prime + b) % prime
            QA_y_square = (pow(QA_x, 3, prime) + (a * QA_x) % prime + b) % prime

            QB_y = pow(QB_y_square, (prime + 1) // 4, prime)
            QA_y = pow(QA_y_square, (prime + 1) // 4, prime)

            ss_alice = double_and_add(prime, a, alice_ephermal_t, (QB_x, QB_y))
            ss_bob = double_and_add(prime, a, bob_ephermal_t, (QA_x, QA_y))

            ss_x_alice = ss_alice[0]
            ss_x_bob = ss_bob[0]

            result_container.write(f"""
                                    **Alice sends to Bob**: {QA_x}\n
                                    **Bob sends to Alice**: {QB_x}\n
                                    **Alice computes shared secret**: {ss_x_alice}\n
                                    **Bob computes shared secret**: {ss_x_bob}\n
                                   """)
            
            if ss_x_alice == ss_x_bob:
                result_container.success("Alice and Bob agreed on same shared secret, protocol successful.")
            
            else:
                result_container.error("Shared secret not the same on both sides, implementation error.")
            
        with col1:
            alice_ephermal = st.text_input("Alice ephermal key", key = "alice_ephermal")
        
        with col2:
            alice_generate_btn = st.button("Generate random ephermal key for Alice", on_click = generate_ecdh_ephermal_key, args = ("alice_ephermal", st.session_state["ecc_standard_options"]))

        col1, col2, _ = st.columns(3, vertical_alignment = "bottom")
        with col1:
            bob_ephermal = st.text_input("Bob ephermal key", key = "bob_ephermal")
        
        with col2:
            bob_generate_btn = st.button("Generate random ephermal key for Bob", on_click = generate_ecdh_ephermal_key, args = ("bob_ephermal", st.session_state["ecc_standard_options"]))

        ecdh_result_container = st.container()
        st.button("Initiate ECDH exchange", on_click = ecdh_exchange, args = (st.session_state["ecc_standard_options"], ecdh_result_container))

    st.markdown(r"""
                ## ECDSA - Elliptic Curve Digital Signature Algorithm
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/ecdsa.png", caption = "Elliptic curve digital signature algorithm pseudocode. Source: [1]")

    st.markdown(r"""
                In previous pseudocode, $x(P)$ stands for the x-coordinate of a point $P \in E(\mathbb{F_p})$, the notation we used for ECDH was $P.x$. Now, let us prove
                that the previous signature generation algorithm is correct, that is if $(s1, s2)$ is a valid signature for document $d$, then we will obtain
                $(v_1G + v_2V).x \equiv s_1 (mod \text{ } q)$:

                $$
                \begin{align*}
                    v_1G + v_2V &= de (d + ss_1)^{-1} (mod \text{ } q) G + s_1e(d + ss_{1})^{-1} (mod \text{ } q) sG \\
                    & = (de(d + ss_1)^{-1}(mod \text{ } q) + ss_1e(d + ss_1)^{-1}(mod \text{ } q))G \\
                    &= (e \underbrace{(d + ss_1)^{-1}(mod \text{ } q)(d + ss_1)}_{1, G \text{ is of order q}})G = eG \\
                    & \text{ Therefore, the signature } (s1, s2) \text{ for document } d \text{ is valid if and only if } (v_1G + v_2V).x \equiv s_1 (mod \text{ } q)
                \end{align*}
                $$

                Unlike ECDH, we cannot avoid redundancy here, for each document we have to keep two numbers $(s1, s2)$ of the same bit length. When it comes
                to compressing documents to $mod \text{ } q$ space, generally a hash function is used. Since all of our ECC standards use generator points of 
                256-bit prime order, we will use **SHA-256** hash function.  
                """)

    with st.container(border = True):
        def create_ecdsa_verification_key():
            st.session_state["create_ecdsa_verification_key_clicked"] = True

            if "s1" in st.session_state: 
                del st.session_state["s1"]

            if "s2" in st.session_state: 
                del st.session_state["s2"]

            if "ecdsa_signature_hex" in st.session_state:
                del st.session_state["ecdsa_signature_hex"]

            standard = ECC_STANDARDS[st.session_state['ecc_standard_options']]
            prime = standard["p"]
            G = standard["G"]
            a = standard["a"]
            order_G = standard["order_G"]

            s = 2 + secrets.randbelow(order_G - 3)
            V = double_and_add(prime, a, s, G)

            st.session_state["s"] = s
            st.session_state["V"] = V

        def ecdsa_verify(container):
            image = st.session_state["uploaded_image"].getvalue()
            d = int(hashlib.sha256(image).hexdigest(), 16)
            
            standard = ECC_STANDARDS[st.session_state['ecc_standard_options']]
            prime = standard["p"]
            G = standard["G"]
            a = standard["a"]
            order_G = standard["order_G"]
            d %= order_G

            V = st.session_state["V"]
            s1 = st.session_state["s1"]
            s2 = st.session_state["s2"]
            s2_inv = pow(s2, -1, order_G)
            v1 = (d * s2_inv) % order_G
            v2 = (s1 * s2_inv) % order_G

            v1_G = double_and_add(prime, a, v1, G)
            v2_V = double_and_add(prime, a, v2, V)
            final_point = ecc_add(prime, a, v1_G, v2_V)
            final_x = final_point[0] % order_G

            container.text(f"Verification code: {d2hex(final_x)}  \nTarget code: {d2hex(s1)}")
            if final_x != s1:
                container.error("Signature failed, implementation error.")

            else:
                container.success("Verification successful!")

        def ecdsa_sign(container):
            if "s" not in st.session_state:
                container.error("You have to generate verification key before creating a signature!")
                return
            
            image = st.session_state["uploaded_image"].getvalue()
            d = int(hashlib.sha256(image).hexdigest(), 16)
            
            standard = ECC_STANDARDS[st.session_state['ecc_standard_options']]
            prime = standard["p"]
            G = standard["G"]
            a = standard["a"]
            order_G = standard["order_G"]

            d %= order_G
            ephermal_key = 2 + secrets.randbelow(order_G - 2)
            eG = double_and_add(prime, a, ephermal_key, G)
            s1 = eG[0] % order_G
            s2 = ((d + st.session_state["s"] * s1) * pow(ephermal_key, -1, order_G)) % order_G

            st.session_state["s1"] = s1
            st.session_state["s2"] = s2

        def image_on_change():
            if "s1" in st.session_state: 
                del st.session_state["s1"]

            if "s2" in st.session_state: 
                del st.session_state["s2"]

            if "ecdsa_signature_hex" in st.session_state:
                del st.session_state["ecdsa_signature_hex"]

        st.header("ECDSA Simulation")
        st.text(f"Chosen ECC standard: {st.session_state['ecc_standard_options']}")
        st.button(f"Create ECDSA verification key", on_click = create_ecdsa_verification_key)
        if "create_ecdsa_verification_key_clicked" in st.session_state:
            verification_key_container = st.container()
            verification_key_container.text(f"Secret signing key: {st.session_state['s']}\nPublic veirifcation key: {str(st.session_state['V'])}")

        st.file_uploader("Upload an image", type = ["jpg", "jpeg", "png"], key = "uploaded_image", on_change = image_on_change)
        sign_container = st.container()

        if st.session_state["uploaded_image"]:
            image = st.session_state["uploaded_image"].getvalue()
            image = Image.open(io.BytesIO(image))
            image_container, ecdsa_container = sign_container.columns(2, vertical_alignment = "top")
            image_container.image(image, use_container_width = True, caption = "Image preview")
            ecdsa_container.button("Generate ECDSA signature", on_click = ecdsa_sign, args = (ecdsa_container,))

            if "s1" in st.session_state:
                signature_upper = d2hex(st.session_state["s1"])
                signature_lower = d2hex(st.session_state["s2"])        
                target = f"{signature_upper}:{signature_lower}"
                st.session_state["ecdsa_signature_hex"] = target
                ecdsa_container.text(f"ECDSA Signature: {st.session_state['ecdsa_signature_hex']}")
                ecdsa_container.button("Verify Signature", on_click = ecdsa_verify, args = (ecdsa_container,))

    st.markdown(r"""
                ### ECC ElGamal
                It's very similar to ElGamal in $\mathbb{F_p}$, we give the pseudocode on the figure below.
                """)
    _, image, __ = st.columns(3)
    image.image("./figs/ecc_elgamal.png", caption = "ECC ElGamal pseudocode. Source: [1]")

    st.markdown(r"""
                However, public key protocols are rarely used for bulk message encryption, and this holds especially for ECC ElGama for the following reasons:

                * Notice that with the previous algorithm we are essentially encrypting points on $E(\mathbb{F_p})$, and there is no obvious way of mapping from 
                text messages to $E(\mathbb{F_p})$ (potential method is discussed in [1]).

                * Both classical ElGamal and ECC ElGamal are significantly slower than symmetric encryption algorithms like AES.

                Therefore for completeness, we only include the pseudocode for ECC ElGamal.
                """)
    st.markdown(r"""
    ## Large prime generation
    When a research institution wants to create a new ECC standard, one of the first steps is to generate a large prime number. For illustrative purposes, 
    we've implemented a prime generator algorithm relying on **Miller-Rabin's** primaility test, [3].
    In order to speed up the algorithm further, we've implemented a parallel version of Miller-Rabin prime generation, and the parallel approach is straightforward -
    each process will generate it's own random number and perform Miller-Rabin test on the given number - the first process that finds a prime reports the result to 
    the parent process, which in turn terminates other child processes, and the whole algorithm terminates.
    """)

    st.number_input("Desired number of bits for the generated prime", min_value = 256, step = 1, key = "prime_bits")
    st.number_input("Number of parallel worker processes", min_value = 2, step = 1, key = "num_processes")
    st.number_input("Number of Miller-Rabin trials to perform", min_value = 10, step = 1, key = "num_trials")

    miller_rabin_container = st.container()

    st.button("Generate prime", on_click = miller_rabin_generator, args = (miller_rabin_container,))
    st.markdown("If you want further reassurance that the found number is actually prime, you can use the following service: https://bigprimes.org/primality-test")

    st.markdown(r"""
                ## Dual_EC_DRBG Controversy
                Random numbers generated on a computer are typically **pseudo-random** - generated numbers appear to be random but under the hood
                they are outputs of a deterministic function. For cryptography, it is crucial to ensure that this deterministic process cannot be reversed -
                otherwise the attacker could unroll the generation process, and predict all future "random" outputs. The algorithms that make this reversal process
                infeasible are known as **CSPRNG - Cryptographically Secure Pseudo-Random Number Generators**.

                In 2006, NIST - National Institute of Standards and Technology released recommended CSPRNG algorithms ([4]). They developed **Dual_EC_DRBG - 
                Dual Elliptic Curve Deterministic Random Bit Generator** algorithm:
                """)

    _, image, __ = st.columns(3)
    image.image("./figs/dual_ec_drbg.png", caption = "High-level overview of Dual_EC_DRBG algorithm. Source: [5]")

    st.markdown(r"""
                Points $P, Q \in E(\mathbb{F_p})$ are fixed, and $s_i$ represents the current state of the random bit generator. $\varphi(x, y)$ is just 
                x-coordinate projection function, LSB stands for least significant portion of a byte block, and in particular the output of this algorithm is 
                $bitlen - 16$ long. This means that the attacker is only missing 16 bits of information, and with $2^{16}$ operations we can relatively easy obtain 
                $r_i Q$. If $P, Q$ were generated truly randomly, this would not be a problem. However, as pointed out in [5], if $P = eQ$ and $e$ was known to 
                the attacker (NSA was the one who generated points $P, Q$), then we have:
                $$
                e(r_i Q) = r_i (e Q) = r_i P
                $$

                and since $s_{i + 1} = \varphi(r_i P)$, we found out the value of $s_{i + 1}$ and can predict every future output!
                """)
    
    _, image, __ = st.columns(3)
    image.image("./figs/dual_ec_drbg_attack.png", caption = "Pseudocode for the previously outlined attack. Source: [5]")

    st.markdown(r"""
                Even though it's infeasible to prove the relation $P = eQ$ due to the difficulty of elliptic curve discrete logarithm problem, paper [5] 
                raised serious security concerns. Furthermore, Edward Snowden leaks from 2013 (6) show that NSA paid RSA security 10 million dollars to incorporate 
                Dual_EC_DRBG algorithm in their cryptographic libraries, and this just intensified previous suspicions.

                The conclusion should be that research institutions should not be blindly trusted. Encryption algorithms are backed by a serious mathematical
                apparatus, and (un)intentionally modifying only a small portion of the algorithm can lead to serious security implications. 
                """)

    st.markdown(r"""
                ## Bibliography
                [1] Hoffstein et al. - An Introduction to Mathematical Cryptography

                [2] Tonelli-Shanks algorithm (https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)

                [3] Miller-Rabin primaility test (https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)

                [4] NIST Special Publication 800-90 Recommendation for Random Number Generation Using Deterministic Random Bit Generators, 2006 (https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90.pdf)

                [5] On the Possibility of a Back Door in the NIST SP800-90 Dual Ec Prng, 2007 (https://rump2007.cr.yp.to/15-shumow.pdf)

                [6]  Dual_EC_DRBG Wikipedia (https://en.wikipedia.org/wiki/Dual_EC_DRBG)
                """)
    
# Required wrapping, otherwise a bunch of warning logs are raised
# Streamlit is not fully compatible with multiprocessing it seems...
if __name__ == "__main__":
    main()