###############################################################################
# (c) 2025 W. Spann Systems Consulting
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###############################################################################

"""
This module provides support for generating sealed Polynomial Pedersen commitments over elliptic curves to any
single-variate polynomial over a finite cyclic field (e.g., where the polynomial's coefficients and its independent `x`
and dependent `y` variables are members of `F_p`, where `p` is a prime number), as well as revealed (unsealed)
polynomial commitments.

Polynomial Pedersen commitments are homomorphic, meaning that commitments to polynomials can be combined (e.g., added,
subtracted, or multiplied by a scalar) to produce commitments to new polynomials without revealing the underlying
polynomials

Additionally, the module supports generating and verifying non-interactive zero-knowledge (NIZK) proofs of evaluation
for such secret polynomials (i.e., a prover who has committed to a secret polynomial can produce an NIZK proof that the
polynomial evaluates to a specific `y` value at a given `x` value, without revealing any information about the
polynomial itself).
"""

from __future__ import annotations

from dataclasses import dataclass

import galois

from galois import Array

from scriptless_zkp.ecc.commitments.pedersen import (
    SealedPedersenCommitment, RevealedPedersenCommitment, PedersenCommitmentContext
)
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


@dataclass(frozen=True, slots=True)
class SealedPolynomialPedersenCommitment:
    coefficient_commitments: list[SealedPedersenCommitment]
    field: type[Array]

    @property
    def degree(self) -> int:
        return len(self.coefficient_commitments) - 1


@dataclass(frozen=True, slots=True)
class RevealedPolynomialPedersenCommitment:
    coefficient_commitments: list[RevealedPedersenCommitment]
    blinding_factors: list[int]
    committed_polynomial: galois.Poly

    @property
    def coefficients(self) -> list[int]:
        return self.committed_polynomial.coeffs.tolist()

    @property
    def degree(self) -> int:
        return self.committed_polynomial.degree

    @property
    def field(self) -> type[Array]:
        return self.committed_polynomial.field


class PolynomialPedersenContext:
    def __init__(self, field: type[Array], pedersen_context: PedersenCommitmentContext):
        if not galois.is_prime(field.characteristic):
            raise ValueError("Field must be a prime field (i.e., F_p where p is prime).")

        self.field = field
        self.pedersen_context = pedersen_context

    @property
    def curve_config(self) -> WeierstrassEllipticCurveConfig:
        return self.pedersen_context.curve_config

    def commit_to_polynomial(
            self,
            polynomial: galois.Poly
    ) -> tuple[SealedPolynomialPedersenCommitment, RevealedPolynomialPedersenCommitment]:
        coefficient_commitments: list[SealedPedersenCommitment] = []
        revealed_coefficient_commitments: list[RevealedPedersenCommitment] = []

        for coeff, i in enumerate(polynomial.coeffs):
            coeff_int: int = int(coeff)
            if not (0 <= coeff_int < self.field.characteristic):
                raise ValueError(
                    f"Polynomial coefficient a_{i} is out of range for the field F_{self.field.characteristic}."
                )

            sealed_commitment, revealed_commitment = self.pedersen_context.commit(coeff_int)

            coefficient_commitments.append(sealed_commitment)
            revealed_coefficient_commitments.append(revealed_commitment)

        return SealedPolynomialPedersenCommitment(
            coefficient_commitments=coefficient_commitments,
            field=self.field
        ), RevealedPolynomialPedersenCommitment(
            coefficient_commitments=revealed_coefficient_commitments,
            blinding_factors=[rc.blinding_factor for rc in revealed_coefficient_commitments],
            committed_polynomial=polynomial
        )

    def generate_evaluation_proof(
            self,
            revealed_commitment: RevealedPolynomialPedersenCommitment,
            x: int
    ) -> tuple[int, int]:
        """
        Generates a non-interactive zero-knowledge (NIZK) proof that the committed polynomial evaluates to `y` at the
        given `x` value, without revealing any information about the polynomial itself.

        0. Precondition: The prover has already committed to a secret polynomial using a Polynomial Pedersen commitment,
        resulting in a `SealedPolynomialPedersenCommitment` and a corresponding `RevealedPolynomialPedersenCommitment`
        (which includes the secret blinding factors used to produce the coefficient commitments).
            a. The prover wants to prove to a verifier that the committed polynomial evaluates to `y` at a specific `x`
               value, without revealing the polynomial itself.
            b. The verifier knows the `SealedPolynomialPedersenCommitment` and the `x` value, but does not know the
               polynomial or its coefficients.
        1. The prover and verifier agree on the `x` value at which the polynomial will be evaluated, which must be in
        the range `[0, p)` where `p` is the field characteristic, with the verifier providing the `x` value to the
        prover.
        2. The prover evaluates the committed polynomial at the given `x` value to obtain `y`.
        3. The prover computes a non-interactive zero-knowledge proof (NIZK) that the committed polynomial evaluates to
        `y` at the given `x` value, using the secret blinding factors from its (revealed) coefficient commitments.
            - This proof `𝜋` is computed as:
                `𝜋 := r_0 + r_1*x + r_2*x^2 + ... + r_d*x^d (mod p)`,
            where `r_i` are the blinding factors for each coefficient commitment, `p` is the field characteristic,
            and `d` is the degree of the polynomial.
        4. The prover sends the pair `(y, 𝜋)` of integers in `Z_p` to the verifier.
        5. The verifier checks that the proof is valid by verifying that the following equation holds
        (i.e., the elliptic curve points produced by the left & right sides are equal), using the coefficient
        commitments from the `SealedPolynomialPedersenCommitment`, provided to the verifier by the prover earlier:
            `y*G + proof*H == C_0 + C_1*x + C_2*x^2 + ... + C_d*x^d (mod p)`,
        where `C_i` are the coefficient commitments, `G` is the Pedersen commitment base point (common generator), and
        `H` is the Pedersen commitment NUMS generator, `p` is the field characteristic, and `d` is the degree of the
        polynomial.

        :param revealed_commitment: the revealed polynomial commitment to the secret polynomial's coefficients, which
               includes the blinding factors used in the coefficient commitments and the committed polynomial itself
               (provided by the prover).
        :param x: the `x` value at which to evaluate the committed polynomial, which must be in the range `[0, p)` where
                  `p` is the field characteristic.
        :return: the pair (y, proof) where `y` is the result of evaluating the committed polynomial at the given `x`
                 value, and `proof` is the NIZK proof that the committed polynomial evaluates to `y` at `x`.
        :raises ValueError: if the provided `x` value is out of range for the field.
        """
        if not (0 <= x < self.field.characteristic):
            raise ValueError(f"Evaluation point x is out of range for the field F_{self.field.characteristic}.")

        # Evaluate the committed polynomial at the given x value.
        y: int = int(revealed_commitment.committed_polynomial(x))

        # Compute a zero-knowledge proof that the committed polynomial evaluates to y at x:
        #     `𝜋 := r_0 + r_1*x + r_2*x^2 + ... + r_d*x^d (mod p)`,
        # where `r_i` are the blinding factors for each coefficient commitment, `p` is the field characteristic,
        # and `d` is the degree of the polynomial.
        proof: int = sum(
            blinding_factor * pow(x, i, self.field.characteristic)
            for i, blinding_factor in enumerate(revealed_commitment.blinding_factors)
        ) % self.field.characteristic

        # Return the evaluation/proof pair (y, 𝜋), of integers modulo `p`.
        return y, proof
