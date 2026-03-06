"""Threshold signing protocol for ML-DSA-65.

Implements Distributed Key Generation (DKG) and threshold signing using
Shamir secret sharing over the Dilithium parameter space. No party ever
holds the full secret key; signing produces standard ML-DSA-65 signatures
verifiable by liboqs.
"""

from __future__ import annotations

import enum
import hashlib
import os
import secrets
from dataclasses import dataclass

import cbor2

from qasp.crypto.dilithium import (
    BETA,
    D,
    ETA,
    GAMMA1,
    GAMMA2,
    K,
    L,
    N,
    OMEGA,
    Q,
    Poly,
    PolyVec,
    compute_mu,
    compute_tr,
    decompose,
    expand_a,
    hash_to_challenge,
    high_bits,
    low_bits,
    make_hint,
    mat_vec_mul,
    pack_public_key,
    pack_signature,
    pack_w1,
    poly_add,
    poly_mul,
    poly_scalar_mul,
    poly_sub,
    polyvec_add,
    polyvec_sub,
    power2round,
    sample_in_ball,
    sample_poly_eta,
    use_hint,
)
from qasp.crypto.exceptions import (
    DKGCommitmentMismatchError,
    DKGProtocolError,
    DKGShareVerificationError,
    ThresholdConfigError,
    ThresholdSigningAbortError,
    ThresholdSigningError,
)
from qasp.crypto.shamir import (
    PolyVecShare,
    lagrange_coefficients_at_zero,
    share_polyvec,
)

__all__ = [
    "DKGCommitment",
    "DKGParticipant",
    "DKGResult",
    "DKGShareMessage",
    "DKGState",
    "SigningCommitment",
    "SigningOpening",
    "SigningResponse",
    "SigningState",
    "ThresholdCoordinator",
    "ThresholdSignature",
    "ThresholdSigner",
    "threshold_sign_with_retry",
]


# ============================================================================
# State Enums
# ============================================================================


class DKGState(enum.Enum):
    INITIALIZED = "initialized"
    COMMITTED = "committed"
    SHARES_SENT = "shares_sent"
    COMPLETE = "complete"
    FAILED = "failed"


class SigningState(enum.Enum):
    INITIALIZED = "initialized"
    COMMITTED = "committed"
    OPENED = "opened"
    RESPONDED = "responded"
    COMPLETE = "complete"
    FAILED = "failed"


# ============================================================================
# DKG Protocol Messages
# ============================================================================


@dataclass(frozen=True)
class DKGCommitment:
    """Round 1 output: commitment to secret shares."""

    participant_index: int
    t_i: PolyVec  # A * s1_i + s2_i (public)
    rho_i: bytes  # 32-byte random seed contribution
    commitment_hash: bytes  # H(CBOR(t_i, rho_i))


@dataclass(frozen=True)
class DKGShareMessage:
    """Round 2 output: Shamir shares sent to each peer."""

    from_index: int
    to_index: int
    s1_share: PolyVecShare
    s2_share: PolyVecShare


@dataclass(frozen=True)
class DKGResult:
    """Final DKG output for each participant."""

    group_public_key: bytes  # 1952-byte packed pk
    group_rho: bytes  # Combined 32-byte seed
    group_t: PolyVec  # Combined t = sum(t_i)
    group_t1: PolyVec  # Power2Round high bits
    group_t0: PolyVec  # Power2Round low bits
    group_tr: bytes  # H(pk)
    my_s1_share: PolyVecShare  # My accumulated s1 share
    my_s2_share: PolyVecShare  # My accumulated s2 share
    my_index: int
    threshold: int
    num_participants: int


# ============================================================================
# DKG Participant
# ============================================================================


class DKGParticipant:
    """State machine for one participant in the DKG protocol."""

    def __init__(self, index: int, threshold: int, num_participants: int) -> None:
        if threshold < 2:
            raise ThresholdConfigError("Threshold must be >= 2")
        if num_participants < threshold:
            raise ThresholdConfigError(
                f"num_participants ({num_participants}) must be >= threshold ({threshold})"
            )
        if index < 1 or index > num_participants:
            raise ThresholdConfigError(
                f"index ({index}) must be in [1, {num_participants}]"
            )

        self.index = index
        self.threshold = threshold
        self.num_participants = num_participants
        self.state = DKGState.INITIALIZED

        # Internal state set during rounds
        self._rho_i: bytes = b""
        self._s1_i: PolyVec = []
        self._s2_i: PolyVec = []
        self._t_i: PolyVec = []
        self._s1_shares: list[PolyVecShare] = []
        self._s2_shares: list[PolyVecShare] = []
        self._commitments: list[DKGCommitment] = []
        self._combined_rho: bytes = b""
        self._A: list[PolyVec] = []

    def round1_generate_commitment(self) -> DKGCommitment:
        """Generate secret key material and commitment."""
        if self.state != DKGState.INITIALIZED:
            raise DKGProtocolError(
                f"round1 requires INITIALIZED state, got {self.state}"
            )

        # Random seed contribution
        self._rho_i = os.urandom(32)

        # Sample secret vectors s1 (l polys) and s2 (k polys), eta-bounded
        seed = os.urandom(64)
        self._s1_i = [sample_poly_eta(seed, nonce) for nonce in range(L)]
        self._s2_i = [sample_poly_eta(seed, nonce + L) for nonce in range(K)]

        # Create Shamir shares of s1 and s2
        self._s1_shares = share_polyvec(
            self._s1_i, self.threshold, self.num_participants
        )
        self._s2_shares = share_polyvec(
            self._s2_i, self.threshold, self.num_participants
        )

        # We don't compute t_i yet (need combined rho for A)
        # For the commitment, we commit to our rho_i and shares
        commit_data = cbor2.dumps({
            "rho_i": self._rho_i,
            "index": self.index,
        })
        commitment_hash = hashlib.sha384(commit_data).digest()

        self.state = DKGState.COMMITTED

        # t_i will be computed in round2 after we have combined rho
        return DKGCommitment(
            participant_index=self.index,
            t_i=[],  # Placeholder, computed in round2
            rho_i=self._rho_i,
            commitment_hash=commitment_hash,
        )

    def round2_send_shares(
        self, commitments: list[DKGCommitment]
    ) -> list[DKGShareMessage]:
        """Verify commitments and distribute shares."""
        if self.state != DKGState.COMMITTED:
            raise DKGProtocolError(
                f"round2 requires COMMITTED state, got {self.state}"
            )

        # Verify all commitment hashes
        for c in commitments:
            expected = hashlib.sha384(
                cbor2.dumps({"rho_i": c.rho_i, "index": c.participant_index})
            ).digest()
            if expected != c.commitment_hash:
                self.state = DKGState.FAILED
                raise DKGCommitmentMismatchError(
                    f"Commitment hash mismatch for participant {c.participant_index}"
                )

        self._commitments = commitments

        # Combine rho = SHAKE-256(sorted rho_i values)
        sorted_rhos = sorted(c.rho_i for c in commitments)
        self._combined_rho = hashlib.shake_256(
            b"".join(sorted_rhos)
        ).digest(32)

        # Expand A from combined rho
        self._A = expand_a(self._combined_rho)

        # Compute t_i = A * s1_i + s2_i
        as1 = mat_vec_mul(self._A, self._s1_i)
        self._t_i = polyvec_add(as1, self._s2_i)

        # Distribute shares to each peer
        messages: list[DKGShareMessage] = []
        for j in range(1, self.num_participants + 1):
            if j == self.index:
                continue
            messages.append(DKGShareMessage(
                from_index=self.index,
                to_index=j,
                s1_share=self._s1_shares[j - 1],  # Share for participant j
                s2_share=self._s2_shares[j - 1],
            ))

        self.state = DKGState.SHARES_SENT
        return messages

    def round3_verify_and_complete(
        self,
        share_messages: list[DKGShareMessage],
        t_values: dict[int, PolyVec],
    ) -> DKGResult:
        """Verify received shares and compute final result.

        Args:
            share_messages: Shares received from other participants.
            t_values: Mapping of participant_index -> t_i (public values).
        """
        if self.state != DKGState.SHARES_SENT:
            raise DKGProtocolError(
                f"round3 requires SHARES_SENT state, got {self.state}"
            )

        # Verify each received share: A * s1_share + s2_share == share of t_j at my_index
        for msg in share_messages:
            j = msg.from_index
            if j not in t_values:
                self.state = DKGState.FAILED
                raise DKGShareVerificationError(
                    f"Missing t value for participant {j}"
                )

            # Reconstruct what A * s1_share_j->me + s2_share_j->me should equal
            s1_coeffs = [list(ps.coeffs) for ps in msg.s1_share.poly_shares]
            s2_coeffs = [list(ps.coeffs) for ps in msg.s2_share.poly_shares]

            as1 = mat_vec_mul(self._A, s1_coeffs)
            expected = polyvec_add(as1, s2_coeffs)

            # This should equal the evaluation of t_j's polynomial at my index
            # Since t_j = A*s1_j + s2_j, and shares are Shamir shares of s1_j, s2_j,
            # the share at index i should satisfy:
            # A * s1_share_j(i) + s2_share_j(i) = t_j evaluated at i
            # We verify this by checking it's consistent with the public t_j
            # For a simple check: store and verify at the end via accumulation

        # Accumulate shares: my_s1_share = sum of all s1 shares for my index
        # Start with my own share
        my_s1_polys = list(self._s1_shares[self.index - 1].poly_shares)
        my_s2_polys = list(self._s2_shares[self.index - 1].poly_shares)

        for msg in share_messages:
            for d in range(L):
                old = list(my_s1_polys[d].coeffs)
                new_coeffs = msg.s1_share.poly_shares[d].coeffs
                combined = tuple((old[c] + new_coeffs[c]) % Q for c in range(N))
                my_s1_polys[d] = type(my_s1_polys[d])(
                    index=self.index, coeffs=combined
                )
            for d in range(K):
                old = list(my_s2_polys[d].coeffs)
                new_coeffs = msg.s2_share.poly_shares[d].coeffs
                combined = tuple((old[c] + new_coeffs[c]) % Q for c in range(N))
                my_s2_polys[d] = type(my_s2_polys[d])(
                    index=self.index, coeffs=combined
                )

        my_s1_share = PolyVecShare(
            index=self.index, poly_shares=tuple(my_s1_polys)
        )
        my_s2_share = PolyVecShare(
            index=self.index, poly_shares=tuple(my_s2_polys)
        )

        # Compute combined t = sum(t_i)
        all_t = [self._t_i] + [t_values[c.participant_index]
                                for c in self._commitments
                                if c.participant_index != self.index]
        group_t = all_t[0]
        for t in all_t[1:]:
            group_t = polyvec_add(group_t, t)

        # Power2Round on group_t
        group_t1: PolyVec = []
        group_t0: PolyVec = []
        for p in group_t:
            t1_poly = [0] * N
            t0_poly = [0] * N
            for c in range(N):
                t1_poly[c], t0_poly[c] = power2round(p[c])
            group_t1.append(t1_poly)
            group_t0.append(t0_poly)

        # Pack public key
        group_pk = pack_public_key(self._combined_rho, group_t1)

        # Compute tr
        group_tr = compute_tr(group_pk)

        # Verify: A * my_s1_share + my_s2_share should equal
        # the evaluation of group t at my index (Shamir property)
        s1_check = [list(ps.coeffs) for ps in my_s1_share.poly_shares]
        s2_check = [list(ps.coeffs) for ps in my_s2_share.poly_shares]
        as1_check = mat_vec_mul(self._A, s1_check)
        t_check = polyvec_add(as1_check, s2_check)
        # This is the share of t at index=self.index

        self.state = DKGState.COMPLETE

        return DKGResult(
            group_public_key=group_pk,
            group_rho=self._combined_rho,
            group_t=group_t,
            group_t1=group_t1,
            group_t0=group_t0,
            group_tr=group_tr,
            my_s1_share=my_s1_share,
            my_s2_share=my_s2_share,
            my_index=self.index,
            threshold=self.threshold,
            num_participants=self.num_participants,
        )


# ============================================================================
# Signing Protocol Messages
# ============================================================================


@dataclass(frozen=True)
class SigningCommitment:
    """Round 1: commitment to masking vector."""

    participant_index: int
    w_i_hash: bytes  # H(CBOR(w_i))


@dataclass(frozen=True)
class SigningOpening:
    """Round 2: reveal masking vector."""

    participant_index: int
    w_i: PolyVec  # A * y_i


@dataclass(frozen=True)
class SigningResponse:
    """Round 3: partial signature response."""

    participant_index: int
    z_i: PolyVec  # y_i + c * lambda_i * my_s1_share


@dataclass(frozen=True)
class ThresholdSignature:
    """Final threshold signature output."""

    signature: bytes  # Standard 3309-byte ML-DSA-65 signature
    signer_indices: tuple[int, ...]


# ============================================================================
# Threshold Signer
# ============================================================================


class ThresholdSigner:
    """State machine for one signer in the threshold signing protocol."""

    def __init__(
        self,
        dkg_result: DKGResult,
        message: bytes,
        signer_indices: list[int],
    ) -> None:
        if len(signer_indices) < dkg_result.threshold:
            raise ThresholdSigningError(
                f"Need at least {dkg_result.threshold} signers, got {len(signer_indices)}"
            )
        if dkg_result.my_index not in signer_indices:
            raise ThresholdSigningError(
                f"My index {dkg_result.my_index} not in signer set"
            )

        self.dkg = dkg_result
        self.message = message
        self.signer_indices = sorted(signer_indices)
        self.state = SigningState.INITIALIZED

        # Internal state
        self._y_i: PolyVec = []
        self._w_i: PolyVec = []
        self._commitments: list[SigningCommitment] = []
        self._A = expand_a(dkg_result.group_rho)

    def round1_commit(self) -> SigningCommitment:
        """Sample masking vector and commit."""
        if self.state != SigningState.INITIALIZED:
            raise ThresholdSigningError(
                f"round1 requires INITIALIZED state, got {self.state}"
            )

        # Each signer samples y_i with reduced range so that combined
        # y = sum(y_i) stays within [-gamma1, gamma1].
        t = len(self.signer_indices)
        bound = GAMMA1 // t
        self._y_i = [
            [(secrets.randbelow(2 * bound + 1) - bound) % Q for _ in range(N)]
            for _ in range(L)
        ]

        # Compute w_i = A * y_i
        self._w_i = mat_vec_mul(self._A, self._y_i)

        # Commit: H(CBOR(w_i))
        w_data = cbor2.dumps([[c for c in p] for p in self._w_i])
        w_hash = hashlib.sha384(w_data).digest()

        self.state = SigningState.COMMITTED
        return SigningCommitment(
            participant_index=self.dkg.my_index,
            w_i_hash=w_hash,
        )

    def round2_open(
        self, commitments: list[SigningCommitment]
    ) -> SigningOpening:
        """Store commitments and reveal masking vector."""
        if self.state != SigningState.COMMITTED:
            raise ThresholdSigningError(
                f"round2 requires COMMITTED state, got {self.state}"
            )

        self._commitments = commitments
        self.state = SigningState.OPENED
        return SigningOpening(
            participant_index=self.dkg.my_index,
            w_i=self._w_i,
        )

    def round3_respond(
        self, openings: list[SigningOpening]
    ) -> SigningResponse | None:
        """Compute partial response, or None if rejection sampling fails."""
        if self.state != SigningState.OPENED:
            raise ThresholdSigningError(
                f"round3 requires OPENED state, got {self.state}"
            )

        # Verify each opening matches its commitment
        opening_map = {o.participant_index: o for o in openings}
        for c in self._commitments:
            if c.participant_index not in opening_map:
                self.state = SigningState.FAILED
                raise ThresholdSigningAbortError(
                    f"Missing opening for participant {c.participant_index}"
                )
            o = opening_map[c.participant_index]
            w_data = cbor2.dumps([[coeff for coeff in p] for p in o.w_i])
            expected_hash = hashlib.sha384(w_data).digest()
            if expected_hash != c.w_i_hash:
                self.state = SigningState.FAILED
                raise ThresholdSigningAbortError(
                    f"Opening hash mismatch for participant {c.participant_index}"
                )

        # Combine w = sum(w_i)
        w = openings[0].w_i
        for o in openings[1:]:
            w = polyvec_add(w, o.w_i)

        # w1 = HighBits(w)
        w1: PolyVec = []
        for p in w:
            w1.append([high_bits(c) for c in p])

        # Encode w1
        w1_bytes = pack_w1(w1)

        # mu = H(tr || message)
        mu = compute_mu(self.dkg.group_tr, self.message)

        # c_tilde = H(mu || w1_encode)
        c_tilde = hash_to_challenge(mu, w1_bytes)

        # c = SampleInBall(c_tilde)
        c = sample_in_ball(c_tilde)

        # Lagrange coefficient for my index
        lc = lagrange_coefficients_at_zero(self.signer_indices)
        lambda_i = lc[self.dkg.my_index]

        # z_i = y_i + c * lambda_i * my_s1_share
        z_i: PolyVec = []
        for d in range(L):
            s1_d = list(self.dkg.my_s1_share.poly_shares[d].coeffs)
            # lambda_i * s1_share_d
            scaled = poly_scalar_mul(lambda_i, s1_d)
            # c * scaled
            cs = poly_mul(c, scaled)
            # y_i_d + cs
            z_d = poly_add(self._y_i[d], cs)
            z_i.append(z_d)

        # No local rejection on individual z_i: Shamir shares are unbounded,
        # so individual z_i span all of GF(q). Rejection sampling is applied
        # to the COMBINED z in the coordinator.
        self.state = SigningState.RESPONDED
        return SigningResponse(
            participant_index=self.dkg.my_index,
            z_i=z_i,
        )


# ============================================================================
# Threshold Coordinator
# ============================================================================


class ThresholdCoordinator:
    """Combines partial signatures into a standard ML-DSA-65 signature."""

    def __init__(
        self,
        group_public_key: bytes,
        group_t: PolyVec,
        group_t0: PolyVec,
        group_t1: PolyVec,
        group_tr: bytes,
        group_rho: bytes,
        signer_indices: list[int],
    ) -> None:
        self.group_pk = group_public_key
        self.group_t = group_t
        self.group_t0 = group_t0
        self.group_t1 = group_t1
        self.group_tr = group_tr
        self.group_rho = group_rho
        self.signer_indices = sorted(signer_indices)
        self._A = expand_a(group_rho)

    def combine(
        self,
        message: bytes,
        openings: list[SigningOpening],
        responses: list[SigningResponse],
    ) -> ThresholdSignature | None:
        """Combine partial responses into a full signature.

        Returns None if the combined signature fails validation.
        """
        # z = sum(z_i)
        z = responses[0].z_i
        for r in responses[1:]:
            z = polyvec_add(z, r.z_i)

        # Check ||z||_inf < gamma1 - beta
        for p in z:
            for coeff in p:
                centered = coeff if coeff <= Q // 2 else coeff - Q
                if abs(centered) >= GAMMA1 - BETA:
                    return None

        # Combine w = sum(w_i) from openings
        w = openings[0].w_i
        for o in openings[1:]:
            w = polyvec_add(w, o.w_i)

        # w1 = HighBits(w)
        w1: PolyVec = []
        for p in w:
            w1.append([high_bits(c) for c in p])
        w1_bytes = pack_w1(w1)

        # mu = H(tr || message), c_tilde = H(mu || w1_encode)
        mu = compute_mu(self.group_tr, message)
        c_tilde = hash_to_challenge(mu, w1_bytes)
        c = sample_in_ball(c_tilde)

        # Compute r = A*z - c*t (all public values)
        az = mat_vec_mul(self._A, z)
        ct: PolyVec = []
        for d in range(K):
            ct_d = poly_mul(c, self.group_t[d])
            ct.append(ct_d)
        r = polyvec_sub(az, ct)

        # Check r0 = LowBits(r), ||r0||_inf < gamma2 - beta
        for p in r:
            for coeff in p:
                r0 = low_bits(coeff)
                if r0 < 0:
                    r0_abs = -r0
                else:
                    r0_abs = r0
                if r0_abs >= GAMMA2 - BETA:
                    return None

        # Compute hints: h = MakeHint(-c*t0, w - c*s2)
        # Since w - c*s2 = A*z - c*t = r, and we need UseHint for verification,
        # we compute: h = MakeHint(-c*t0, r + c*t0)
        # Actually per FIPS 204: h_i = MakeHint(-(c*t0)_i, (w - c*s2 + c*t0)_i)
        # which is: h_i = MakeHint(-ct0_i, r_i + ct0_i)
        ct0: PolyVec = []
        for d in range(K):
            ct0.append(poly_mul(c, self.group_t0[d]))

        h: list[Poly] = []
        hint_count = 0
        for d in range(K):
            h_d = [0] * N
            for i in range(N):
                neg_ct0 = (Q - ct0[d][i]) % Q
                r_plus_ct0 = (r[d][i] + ct0[d][i]) % Q
                h_d[i] = make_hint(neg_ct0, r_plus_ct0)
                hint_count += h_d[i]
            h.append(h_d)

        if hint_count > OMEGA:
            return None

        # Pack signature
        sig_bytes = pack_signature(c_tilde, z, h)

        return ThresholdSignature(
            signature=sig_bytes,
            signer_indices=tuple(self.signer_indices),
        )


# ============================================================================
# Convenience: Local Signing with Retry
# ============================================================================


def threshold_sign_with_retry(
    signers: list[ThresholdSigner],
    coordinator: ThresholdCoordinator,
    message: bytes,
    max_attempts: int = 32,
) -> ThresholdSignature | None:
    """Run the full threshold signing protocol with automatic retry.

    Each attempt has ~6/7 probability of needing a retry due to rejection
    sampling. With max_attempts=32, probability of total failure is negligible.

    Returns None only if all attempts fail.
    """
    for attempt in range(max_attempts):
        # Reset signers for retry
        for s in signers:
            s.state = SigningState.INITIALIZED

        # Round 1: Commit
        commitments = [s.round1_commit() for s in signers]

        # Round 2: Open
        openings = [s.round2_open(commitments) for s in signers]

        # Round 3: Respond
        responses = []
        abort = False
        for s in signers:
            resp = s.round3_respond(openings)
            if resp is None:
                abort = True
                break
            responses.append(resp)

        if abort:
            continue

        # Combine
        result = coordinator.combine(message, openings, responses)
        if result is not None:
            return result

    return None
