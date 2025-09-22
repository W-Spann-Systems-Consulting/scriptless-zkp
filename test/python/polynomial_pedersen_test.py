import galois

from galois import GF

from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.commitments.pedersen import PedersenCommitmentContext
from scriptless_zkp.ecc.commitments.polynomial_pedersen import PolynomialPedersenContext, PolynomialPedersenEvaluationProof


pedersen_context = PedersenCommitmentContext.for_curve(curve_config=WeierstrassEllipticCurveConfig.secp256r1())
GF17 = GF(17)
poly_context = PolynomialPedersenContext(field=GF17, pedersen_context=pedersen_context)
poly: galois.Poly = galois.Poly([1, 0, 13, 7, 4, 10, 0, 2, 16], field=GF17)
sealed_poly_commitment, revealed_poly_commitment = poly_context.commit_to_polynomial(poly)

# poly(6)
# >> GF(10, order=17)

proof: PolynomialPedersenEvaluationProof = revealed_poly_commitment.generate_evaluation_proof(6)

# proof
# >> PolynomialPedersenEvaluationProof(x=6, y=10, proof=1)

proof.verify(sealed_poly_commitment)
