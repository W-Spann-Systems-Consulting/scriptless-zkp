import galois

from galois import GF, Poly

from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.commitments.pedersen import PedersenCommitmentContext
from scriptless_zkp.ecc.commitments.polynomial_pedersen import PolynomialPedersenContext, PolynomialPedersenEvaluationProof


pedersen_context = PedersenCommitmentContext.for_curve(curve_config=WeierstrassEllipticCurveConfig.secp256r1())
q: int = pedersen_context.curve_config.order

# Create a Galois field GF(q) with the same characteristic as the underlying elliptic curve's subgroup order, which
# will be used for a polynomial's coefficients.
GFq = GF(
    q,
    primitive_element=7,
    verify=False,
    compile='python-calculate'
)

poly_context = PolynomialPedersenContext(field=GFq, pedersen_context=pedersen_context)
poly: galois.Poly = galois.Poly([1, 0, 13, 7, 4, 10, 0, 2, 16], field=GFq)
sealed_poly_commitment, revealed_poly_commitment = poly_context.commit_to_polynomial(poly)

proof: PolynomialPedersenEvaluationProof = revealed_poly_commitment.generate_evaluation_proof(6)

print(f"Polynomial Pedersen evaluation proof: {proof!s}")
# Output:
# Polynomial Pedersen evaluation proof: PolynomialPedersenEvaluationProof(x=6, y=2347948, proof=31967413868870876678876198191292635241895746460136425638239270077817015070621)

if proof.verify(sealed_poly_commitment):
    print("Valid Polynomial Pedersen evaluation proof")
else:
    print("Invalid Polynomial Pedersen evaluation proof")
