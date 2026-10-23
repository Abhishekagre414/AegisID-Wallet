/**
 * The claims a holder copy of a credential contains.
 * New credentials keep claims in unsigned `disclosures` ([salt, name, value] triples) next to
 * a signed commitment list; legacy credentials keep them directly in credentialSubject.
 */
export function getClaims(vc) {
  if (!vc) return {};
  if (Array.isArray(vc.disclosures)) {
    return Object.fromEntries(vc.disclosures.map(([, name, value]) => [name, value]));
  }
  // eslint-disable-next-line no-unused-vars
  const { id, _sd, _sd_alg, ...claims } = vc.credentialSubject || {};
  return claims;
}
