"""Native primitives only; no archive acceptance policy or deterministic research keys."""
import hashlib
import oqs
from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.exceptions import InvalidSignature
ALG_NAMES={1:'ECDSA-P256-SHA256',2:'ML-DSA-65',3:'SLH_DSA_PURE_SHA2_192F'}
PK_LEN={1:65,2:1952,3:48}; SIG_LEN={1:64,2:3309,3:35664}
class Key:
 def __init__(self,alg):
  self.alg=alg
  if alg==1:
   self.secret=ec.generate_private_key(ec.SECP256R1())
   self.public=self.secret.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
  else:
   self.secret=oqs.Signature(ALG_NAMES[alg]);self.public=self.secret.generate_keypair()
  assert len(self.public)==PK_LEN[alg]
 def sign(self,msg):
  if self.alg==1:
   r,s=utils.decode_dss_signature(self.secret.sign(msg,ec.ECDSA(hashes.SHA256())))
   sig=r.to_bytes(32,'big')+s.to_bytes(32,'big')
  else:sig=self.secret.sign(msg)
  assert len(sig)==SIG_LEN[self.alg]
  return sig
 def close(self):
  if self.alg!=1:self.secret.free()
_VERIFIERS={a:oqs.Signature(ALG_NAMES[a]) for a in (2,3)}
def verify(alg,pub,msg,sig):
 if alg not in PK_LEN or len(pub)!=PK_LEN[alg] or len(sig)!=SIG_LEN[alg]:return False
 try:
  if alg==1:
   public=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),pub)
   public.verify(utils.encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),msg,ec.ECDSA(hashes.SHA256()))
   return True
  return bool(_VERIFIERS[alg].verify(msg,sig,pub))
 except (ValueError,InvalidSignature,RuntimeError):return False
