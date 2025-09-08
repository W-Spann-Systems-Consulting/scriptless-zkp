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
from scriptless_zkp.ecc.ecc_utils import generate_random_nonce
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
