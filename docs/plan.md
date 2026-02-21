Implement the following plan:                                                                                                                                 
                                                                                                                                                                
  # Capability Token Engine Implementation Plan                                                                                                                 
                                                                                                                                                                
  ## Overview                                                                                                                                                   
  Implement `src/qasp/protocol/capability.py` - a CBOR-encoded, ML-DSA-65 signed capability token system with support for attenuation, splitting, and           
  delegation chain verification.                                                                                                                                
                                                                                                                                                                
  ## Files to Modify                                                                                                                                            
  - **Primary**: `src/qasp/protocol/capability.py` (replace stub with full implementation)                                                                      
  - **New Test**: `tests/protocol/test_capability.py`                                                                                                           
                                                                                                                                                                
  ## Reference Files (patterns to follow)                                                                                                                       
  - `src/qasp/identity/binding.py` - CBOR encoding, delegation chains, attenuation pattern                                                                      
  - `src/qasp/protocol/exceptions.py` - Exception hierarchy with alert codes                                                                                    
  - `src/qasp/crypto/signatures.py` - `sign()` and `verify()` functions                                                                                         
                                                                                                                                                                
  ---                                                                                                                                                           
                                                                                                                                                                
  ## Implementation Steps                                                                                                                                       
                                                                                                                                                                
  ### Step 1: Exception Hierarchy                                                                                                                               
  Add capability-specific exceptions following the `HandshakeError` pattern:                                                                                    
                                                                                                                                                                
  ```python                                                                                                                                                     
  class CapabilityError(ProtocolError):                                                                                                                         
  """Base exception for capability token errors."""                                                                                                             
  alert_code: int = 0                                                                                                                                           
                                                                                                                                                                
  class TokenExpiredError(CapabilityError):                                                                                                                     
  alert_code: int = 45                                                                                                                                          
                                                                                                                                                                
  class TokenNotYetValidError(CapabilityError):                                                                                                                 
  alert_code: int = 46                                                                                                                                          
                                                                                                                                                                
  class InvalidTokenError(CapabilityError):                                                                                                                     
  alert_code: int = 51                                                                                                                                          
                                                                                                                                                                
  class TokenConstraintViolation(CapabilityError):                                                                                                              
  alert_code: int = 49                                                                                                                                          
                                                                                                                                                                
  class AttenuationError(CapabilityError):                                                                                                                      
  alert_code: int = 48                                                                                                                                          
                                                                                                                                                                
  class DelegationDepthExceeded(CapabilityError):                                                                                                               
  alert_code: int = 47                                                                                                                                          
                                                                                                                                                                
  class InvalidDelegationChainError(CapabilityError):                                                                                                           
  alert_code: int = 44                                                                                                                                          
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 2: Core Data Structures                                                                                                                              
                                                                                                                                                                
  **VerbSet** - Immutable set of permitted operations:                                                                                                          
  ```python                                                                                                                                                     
  @dataclass(frozen=True)                                                                                                                                       
  class VerbSet:                                                                                                                                                
  verbs: frozenset[str]                                                                                                                                         
                                                                                                                                                                
  def issubset(self, other: VerbSet) -> bool                                                                                                                    
  def intersection(self, other: VerbSet) -> VerbSet                                                                                                             
  ```                                                                                                                                                           
                                                                                                                                                                
  **Constraints** - Token usage constraints (all optional):                                                                                                     
  ```python                                                                                                                                                     
  @dataclass(frozen=True)                                                                                                                                       
  class Constraints:                                                                                                                                            
  not_before: datetime | None = None                                                                                                                            
  not_after: datetime | None = None                                                                                                                             
  quantity_limit: int | None = None                                                                                                                             
  quantity_unit: str = ""                                                                                                                                       
  rate_limit: int | None = None                                                                                                                                 
  rate_period_seconds: int = 3600                                                                                                                               
  max_spend: int | None = None                                                                                                                                  
  spend_currency: str = ""                                                                                                                                      
  data_scope: frozenset[str] = field(default_factory=frozenset)                                                                                                 
  purpose: str = ""                                                                                                                                             
                                                                                                                                                                
  def is_tighter_than(self, other: Constraints) -> bool                                                                                                         
  def tighten(self, delta: Constraints) -> Constraints                                                                                                          
  ```                                                                                                                                                           
                                                                                                                                                                
  **CapabilityToken** - Main token structure:                                                                                                                   
  ```python                                                                                                                                                     
  @dataclass(frozen=True)                                                                                                                                       
  class CapabilityToken:                                                                                                                                        
  token_id: bytes                    # SHA-384(issuer+nonce)[:32]                                                                                               
  issuer_did: DID                    # Token issuer                                                                                                             
  subject_did: DID                   # Token holder                                                                                                             
  audience_did: DID | None           # Service provider (optional)                                                                                              
  resource_uri: str                  # ARM-style URI                                                                                                            
  verbs: VerbSet                     # Permitted operations                                                                                                     
  constraints: Constraints           # Usage constraints                                                                                                        
  issued_at: datetime                                                                                                                                           
  nonce: bytes                       # 16 bytes                                                                                                                 
  signature: bytes                   # ML-DSA-65 signature                                                                                                      
  parent_token_hash: bytes | None    # For delegated tokens                                                                                                     
  max_delegation_depth: int = 0                                                                                                                                 
  delegation_chain_length: int = 0                                                                                                                              
                                                                                                                                                                
  def to_cbor(self) -> bytes                                                                                                                                    
  def compute_hash(self) -> bytes                                                                                                                               
  @classmethod                                                                                                                                                  
  def from_cbor(cls, data: bytes) -> CapabilityToken                                                                                                            
  ```                                                                                                                                                           
                                                                                                                                                                
  **TokenUsage** - Runtime tracking (for constraint verification):                                                                                              
  ```python                                                                                                                                                     
  @dataclass                                                                                                                                                    
  class TokenUsage:                                                                                                                                             
  quantity_consumed: int = 0                                                                                                                                    
  operations_in_period: int = 0                                                                                                                                 
  period_start: datetime | None = None                                                                                                                          
  total_spend: int = 0                                                                                                                                          
  data_accessed: set[str] = field(default_factory=set)                                                                                                          
  declared_purpose: str = ""                                                                                                                                    
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 3: CBOR Encoding                                                                                                                                     
  Follow `binding.py` pattern with deterministic ordering:                                                                                                      
  ```python                                                                                                                                                     
  def _encode_token_data(...) -> bytes:                                                                                                                         
  token_data = {                                                                                                                                                
  "token_id": token_id.hex(),                                                                                                                                   
  "issuer": str(issuer_did),                                                                                                                                    
  "subject": str(subject_did),                                                                                                                                  
  "audience": str(audience_did) if audience_did else None,                                                                                                      
  "resource": resource_uri,                                                                                                                                     
  "verbs": sorted(verbs.verbs),  # Sorted for determinism                                                                                                       
  "constraints": {...},                                                                                                                                         
  "iat": issued_at.isoformat(),                                                                                                                                 
  "nonce": nonce.hex(),                                                                                                                                         
  "parent": parent_token_hash.hex() if parent_token_hash else None,                                                                                             
  "max_depth": max_delegation_depth,                                                                                                                            
  "chain_len": delegation_chain_length,                                                                                                                         
  }                                                                                                                                                             
  return cbor2.dumps(token_data)                                                                                                                                
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 4: Token Creation                                                                                                                                    
  ```python                                                                                                                                                     
  def create_token(                                                                                                                                             
  issuer_did: DID,                                                                                                                                              
  issuer_secret_key: bytes,                                                                                                                                     
  subject_did: DID,                                                                                                                                             
  resource_uri: str,                                                                                                                                            
  verbs: set[str] | VerbSet,                                                                                                                                    
  constraints: Constraints | None = None,                                                                                                                       
  audience_did: DID | None = None,                                                                                                                              
  max_delegation_depth: int = 0,                                                                                                                                
  validity_seconds: int = 3600,                                                                                                                                 
  ) -> CapabilityToken:                                                                                                                                         
  # 1. Generate nonce, set timestamps                                                                                                                           
  # 2. Compute token_id = SHA-384(str(issuer_did) + nonce)[:32]                                                                                                 
  # 3. Encode to CBOR (without signature)                                                                                                                       
  # 4. Sign with ML-DSA-65                                                                                                                                      
  # 5. Return frozen CapabilityToken                                                                                                                            
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 5: Token Verification                                                                                                                                
  ```python                                                                                                                                                     
  def verify_token(                                                                                                                                             
  token: CapabilityToken,                                                                                                                                       
  issuer_public_key: bytes,                                                                                                                                     
  check_expiry: bool = True,                                                                                                                                    
  usage: TokenUsage | None = None,                                                                                                                              
  ) -> bool:                                                                                                                                                    
  # 1. Verify ML-DSA-65 signature                                                                                                                               
  # 2. Check not_before/not_after constraints                                                                                                                   
  # 3. If usage provided, verify constraint compliance                                                                                                          
  # Raises: InvalidTokenError, TokenExpiredError, TokenConstraintViolation                                                                                      
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 6: Attenuation                                                                                                                                       
  Implement `att(T, Δ) → T'` where V_T' ⊆ V_T and constraints are tighter:                                                                                      
  ```python                                                                                                                                                     
  def attenuate_token(                                                                                                                                          
  parent_token: CapabilityToken,                                                                                                                                
  delegator_secret_key: bytes,                                                                                                                                  
  new_subject_did: DID,                                                                                                                                         
  reduced_verbs: VerbSet | None = None,                                                                                                                         
  tightened_constraints: Constraints | None = None,                                                                                                             
  ) -> CapabilityToken:                                                                                                                                         
  # 1. Validate parent not expired                                                                                                                              
  # 2. Validate delegation depth > 0                                                                                                                            
  # 3. Verify verbs subset of parent verbs                                                                                                                      
  # 4. Verify constraints are monotonically tighter                                                                                                             
  # 5. Set parent_token_hash = parent.compute_hash()                                                                                                            
  # 6. Decrement max_delegation_depth, increment chain_length                                                                                                   
  # 7. Sign with delegator's key                                                                                                                                
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 7: Splitting                                                                                                                                         
  Partition quantity constraints:                                                                                                                               
  ```python                                                                                                                                                     
  def split_token(                                                                                                                                              
  token: CapabilityToken,                                                                                                                                       
  holder_secret_key: bytes,                                                                                                                                     
  split_amounts: list[int],                                                                                                                                     
  new_subject_dids: list[DID] | None = None,                                                                                                                    
  ) -> list[CapabilityToken]:                                                                                                                                   
  # 1. Verify token has quantity_limit                                                                                                                          
  # 2. Verify sum(amounts) <= quantity_limit                                                                                                                    
  # 3. For each amount: create attenuated token with quantity_limit=amount                                                                                      
  # Example: 2 vCPU-h → [1 vCPU-h, 1 vCPU-h]                                                                                                                    
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 8: Delegation Chain Verification                                                                                                                     
  ```python                                                                                                                                                     
  def verify_delegation_chain(                                                                                                                                  
  tokens: list[CapabilityToken],                                                                                                                                
  root_issuer_public_key: bytes,                                                                                                                                
  did_resolver: DIDResolver | None = None,                                                                                                                      
  check_expiry: bool = True,                                                                                                                                    
  ) -> bool:                                                                                                                                                    
  # 1. Verify first token has no parent (is root)                                                                                                               
  # 2. Verify first token with root_issuer_public_key                                                                                                           
  # 3. For each subsequent token:                                                                                                                               
  #    a. Verify parent_token_hash matches previous.compute_hash()                                                                                              
  #    b. Verify chain_length increments, depth decrements                                                                                                      
  #    c. Verify verbs ⊆ parent verbs                                                                                                                           
  #    d. Verify constraints are tighter                                                                                                                        
  #    e. Resolve issuer DID → public key, verify signature                                                                                                     
  ```                                                                                                                                                           
                                                                                                                                                                
  ### Step 9: DID Resolution Protocol                                                                                                                           
  ```python                                                                                                                                                     
  class DIDResolver(Protocol):                                                                                                                                  
  def resolve(self, did: DID) -> bytes: ...                                                                                                                     
                                                                                                                                                                
  class LocalDIDResolver:                                                                                                                                       
  def __init__(self, registry: DIDRegistry): ...                                                                                                                
  def resolve(self, did: DID) -> bytes: ...                                                                                                                     
  ```                                                                                                                                                           
                                                                                                                                                                
  ---                                                                                                                                                           
                                                                                                                                                                
  ## Tests to Write                                                                                                                                             
                                                                                                                                                                
  Create `tests/protocol/test_capability.py`:                                                                                                                   
                                                                                                                                                                
  1. **Token Creation**: `test_create_token`, `test_token_has_signature`, `test_token_cbor_roundtrip`                                                           
  2. **Verification**: `test_verify_valid_token`, `test_verify_wrong_key_fails`, `test_verify_expired_token`                                                    
  3. **Constraints**: `test_quantity_constraint`, `test_rate_constraint`, `test_data_scope_constraint`                                                          
  4. **Attenuation**: `test_attenuate_token`, `test_attenuate_reduces_verbs`, `test_cannot_expand_verbs`                                                        
  5. **Splitting**: `test_split_token`, `test_split_preserves_verbs`, `test_split_exceeds_quantity_fails`                                                       
  6. **Chain Verification**: `test_verify_chain`, `test_broken_chain_fails`, `test_max_depth_3_verified`                                                        
                                                                                                                                                                
  ---                                                                                                                                                           
                                                                                                                                                                
  ## Verification Plan                                                                                                                                          
                                                                                                                                                                
  ```bash                                                                                                                                                       
  # Run linting                                                                                                                                                 
  ruff check src/qasp/protocol/capability.py                                                                                                                    
  mypy src/qasp/protocol/capability.py                                                                                                                          
                                                                                                                                                                
  # Run tests                                                                                                                                                   
  pytest tests/protocol/test_capability.py -v                                                                                                                   
                                                                                                                                                                
  # Verify key scenarios                                                                                                                                        
  # 1. Create token → verify → passes                                                                                                                           
  # 2. Attenuate token → verify chain → passes                                                                                                                  
  # 3. Split 2 vCPU-h → [1, 1] → both verify                                                                                                                    
  # 4. Delegation depth 3 chain → verify_delegation_chain passes                                                                                                
  ```                                                                                                                                                           
                                                                                                                                                                
  ---                                                                                                                                                           
                                                                                                                                                                
  ## Dependencies                                                                                                                                               
  - `cbor2` (already installed)                                                                                                                                 
  - `qasp.crypto.signatures` (ML-DSA-65)                                                                                                                        
  - `qasp.identity.did` (DID class)                                                                                                                             
  - `qasp.protocol.states` (ProtocolError base)                                                                                                                 
                                                                                                                                                                
                                                                                                                                                                
  If you need specific details from before exiting plan mode (like exact code snippets, error messages, or content you generated), read the full transcript     
  at: C:\Users\wooai\.claude\projects\C--Users-wooai-Documents-GitHub-QASP\3d08dd93-3651-440a-b857-4e3eb5075efd.jsonl 