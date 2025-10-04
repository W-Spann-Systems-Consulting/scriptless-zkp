import galois

from galois import GF, Poly

from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.commitments.pedersen import PedersenCommitmentContext
from scriptless_zkp.ecc.commitments.polynomial_pedersen import PolynomialPedersenContext, PolynomialPedersenEvaluationProof


pedersen_context = PedersenCommitmentContext.for_curve(curve_config=WeierstrassEllipticCurveConfig.secp256r1())
# GF17 = GF(17)

# Optimization: Provide the (Conway) irreducible polynomial basis for the Galois field & a primitive element explicitly.
#   <class 'galois.GF(115792089210356248762697446949407573529996955224135760342422259061068512044369, primitive_element='7', irreducible_poly='x + 115792089210356248762697446949407573529996955224135760342422259061068512044362')'>
irreducible_poly: Poly = galois.Poly([1, 115792089210356248762697446949407573529996955224135760342422259061068512044362])
GFq = GF(
    pedersen_context.curve_config.order,
    irreducible_poly=Poly.Str("x + 115792089210356248762697446949407573529996955224135760342422259061068512044362"),  # x + (q-7)
    primitive_element=7,
    verify=False,
    compile='python-calculate'
)
# GFq = GF(int(pedersen_context.curve_config.order))


poly_context = PolynomialPedersenContext(field=GFq, pedersen_context=pedersen_context)
poly: galois.Poly = galois.Poly([1, 0, 13, 7, 4, 10, 0, 2, 16], field=GFq)
sealed_poly_commitment, revealed_poly_commitment = poly_context.commit_to_polynomial(poly)

# poly(6)
# >> GF(10, order=17)

proof: PolynomialPedersenEvaluationProof = revealed_poly_commitment.generate_evaluation_proof(6)

# proof
# >> PolynomialPedersenEvaluationProof(x=6, y=10, proof=1)

if proof.verify(sealed_poly_commitment):
    print("Valid Pedersen Polynomial evaluation proof")
else:
    print("Invalid Pedersen Polynomial evaluation proof")
