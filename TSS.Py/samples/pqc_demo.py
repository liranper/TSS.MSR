"""
PQC Demo Script for TSS.Py — TPM 2.0 Library Spec v1.85
=========================================================
Demonstrates ML-DSA (signing/verification) and ML-KEM (encapsulation/decapsulation)
against a running TCG TPM-Internal simulator over TCP.

Usage:
    python pqc_demo.py [--host HOST] [--port PORT]

Default connection: 127.0.0.1:2321 (TCG TPM-Internal simulator default)

Requirements:
    - A running TCG TPM-Internal simulator that supports TPM 2.0 v1.85 PQC commands.
    - TSS.Py installed (or run from the TSS.Py root with: python -m samples.pqc_demo)
"""

import sys
import os
import argparse

# Allow running directly from the samples/ directory or from TSS.Py root
_samples_dir = os.path.dirname(os.path.abspath(__file__))
_tss_py_dir = os.path.dirname(_samples_dir)
sys.path.insert(0, _tss_py_dir)

from src.Tpm import *


def parse_args():
    parser = argparse.ArgumentParser(description='PQC demo for TSS.Py (TPM 2.0 v1.85)')
    parser.add_argument('--host', default='127.0.0.1', help='Simulator host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=2321, help='Simulator port (default: 2321)')
    return parser.parse_args()


def build_mldsa_template(security_strength=TPM_MLDSA_SECURITY_STRENGTH.MLDSA_65):
    """ Build a TPMT_PUBLIC template for an ML-DSA primary key.

    Args:
        security_strength: One of TPM_MLDSA_SECURITY_STRENGTH.MLDSA_44/65/87

    Returns:
        TPMT_PUBLIC template
    """
    # allowExternalMu=0 (NO): disallow TPM2_SignDigest/VerifyDigestSignature
    parms = TPMS_MLDSA_PARMS(security_strength, 0)
    unique = TPM2B_MLDSA_PUBLIC_KEY()
    return TPMT_PUBLIC(
        nameAlg=TPM_ALG_ID.SHA256,
        objectAttributes=(
            TPMA_OBJECT.restricted |
            TPMA_OBJECT.sign |
            TPMA_OBJECT.fixedTPM |
            TPMA_OBJECT.fixedParent |
            TPMA_OBJECT.sensitiveDataOrigin |
            TPMA_OBJECT.userWithAuth
        ),
        authPolicy=None,
        parameters=parms,
        unique=unique
    )


def build_mlkem_template(security_strength=TPM_MLKEM_SECURITY_STRENGTH.MLKEM_768):
    """ Build a TPMT_PUBLIC template for an ML-KEM primary key.

    Args:
        security_strength: One of TPM_MLKEM_SECURITY_STRENGTH.MLKEM_512/768/1024

    Returns:
        TPMT_PUBLIC template
    """
    # symmetric=None means TPM_ALG_NULL (unrestricted decryption key)
    parms = TPMS_MLKEM_PARMS(symmetric=None, parameterSet=security_strength)
    unique = TPM2B_MLKEM_PUBLIC_KEY()
    return TPMT_PUBLIC(
        nameAlg=TPM_ALG_ID.SHA256,
        objectAttributes=(
            TPMA_OBJECT.decrypt |
            TPMA_OBJECT.fixedTPM |
            TPMA_OBJECT.fixedParent |
            TPMA_OBJECT.sensitiveDataOrigin |
            TPMA_OBJECT.userWithAuth
        ),
        authPolicy=None,
        parameters=parms,
        unique=unique
    )


def demo_mldsa(tpm):
    """ ML-DSA demo: create a primary key, sign a message, verify the signature. """
    print('\n=== ML-DSA Demo ===')
    mldsa_handle = None
    sign_seq = None
    verify_seq = None

    try:
        # Create ML-DSA primary key
        print('Creating ML-DSA-65 primary key under TPM_RH_OWNER...')
        sensitive = TPMS_SENSITIVE_CREATE()
        inPublic = build_mldsa_template(TPM_MLDSA_SECURITY_STRENGTH.MLDSA_65)

        tpm.allowErrors()
        res = tpm.CreatePrimary(
            TPM_HANDLE(TPM_RH.OWNER),
            sensitive,
            inPublic,
            b'',       # outsideInfo
            []         # creationPCR
        )
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('CreatePrimary(MLDSA)', tpm.lastResponseCode)
            return False

        mldsa_handle = res.handle
        print(f'  ML-DSA key created, handle: 0x{int(mldsa_handle.handle):08X}')

        # Sign a message using SignSequenceStart + SequenceUpdate + SignSequenceComplete
        message = b'Hello, ML-DSA world! This message is signed by the TPM.'
        CHUNK_SIZE = 1024

        # Start signing sequence
        # auth=None: no authorization value for the sequence object
        # context=None: empty TPM2B_SIGNATURE_CTX (correct for pure ML-DSA)
        print('Starting ML-DSA signing sequence...')
        tpm.allowErrors()
        sign_seq = tpm.SignSequenceStart(
            mldsa_handle,   # keyHandle: ML-DSA signing key (auth: USER)
            None,           # auth: auth value for the returned sequence handle
            None            # context: TPM2B_SIGNATURE_CTX (empty for pure ML-DSA)
        )
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('SignSequenceStart', tpm.lastResponseCode)
            return False
        print(f'  Signing sequence handle: 0x{int(sign_seq.handle):08X}')

        # Feed message data via SequenceUpdate
        offset = 0
        while offset < len(message):
            chunk = message[offset:offset + CHUNK_SIZE]
            tpm.SequenceUpdate(sign_seq, chunk)
            if tpm.lastResponseCode != TPM_RC.SUCCESS:
                _handle_unsupported('SequenceUpdate (sign)', tpm.lastResponseCode)
                return False
            offset += CHUNK_SIZE

        # Complete signing: provide sequenceHandle, keyHandle, and final buffer
        print('Completing ML-DSA signing sequence...')
        tpm.allowErrors()
        signature = tpm.SignSequenceComplete(
            sign_seq,       # sequenceHandle (auth: USER)
            mldsa_handle,   # keyHandle (auth: USER)
            b''             # buffer: final (empty) message chunk
        )
        sign_seq = None  # sequence handle is flushed automatically on complete
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('SignSequenceComplete', tpm.lastResponseCode)
            return False
        print(f'  Signature obtained ({type(signature).__name__})')

        # Verify signature using VerifySequenceStart + SequenceUpdate + VerifySequenceComplete
        # hint=None: empty TPM2B_SIGNATURE_HINT (correct for ML-DSA)
        # context=None: empty TPM2B_SIGNATURE_CTX (correct for pure ML-DSA)
        print('Starting ML-DSA verification sequence...')
        tpm.allowErrors()
        verify_seq = tpm.VerifySequenceStart(
            mldsa_handle,   # keyHandle: ML-DSA verify key (no auth needed)
            None,           # auth: auth value for the returned sequence handle
            None,           # hint: TPM2B_SIGNATURE_HINT (empty for ML-DSA)
            None            # context: TPM2B_SIGNATURE_CTX (empty for pure ML-DSA)
        )
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('VerifySequenceStart', tpm.lastResponseCode)
            return False
        print(f'  Verification sequence handle: 0x{int(verify_seq.handle):08X}')

        # Feed same message data
        offset = 0
        while offset < len(message):
            chunk = message[offset:offset + CHUNK_SIZE]
            tpm.SequenceUpdate(verify_seq, chunk)
            if tpm.lastResponseCode != TPM_RC.SUCCESS:
                _handle_unsupported('SequenceUpdate (verify)', tpm.lastResponseCode)
                return False
            offset += CHUNK_SIZE

        # Complete verification: provide sequenceHandle, keyHandle, and signature
        # No buffer field — the accumulated message lives in the sequence object
        print('Completing ML-DSA verification sequence...')
        tpm.allowErrors()
        validation = tpm.VerifySequenceComplete(
            verify_seq,     # sequenceHandle (no auth)
            mldsa_handle,   # keyHandle (no auth)
            signature       # the ML-DSA signature to verify
        )
        verify_seq = None  # flushed on complete
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('VerifySequenceComplete', tpm.lastResponseCode)
            return False

        print('  ML-DSA signature verification SUCCEEDED!')
        return True

    except Exception as exc:
        print(f'  ML-DSA demo error: {exc}')
        return False

    finally:
        # Clean up any open sequence handles
        if sign_seq is not None:
            try:
                tpm.allowErrors()
                tpm.FlushContext(sign_seq)
            except Exception:
                pass
        if verify_seq is not None:
            try:
                tpm.allowErrors()
                tpm.FlushContext(verify_seq)
            except Exception:
                pass
        if mldsa_handle is not None:
            try:
                tpm.allowErrors()
                tpm.FlushContext(mldsa_handle)
            except Exception:
                pass


def demo_mlkem(tpm):
    """ ML-KEM demo: create a primary key, encapsulate, decapsulate, compare secrets. """
    print('\n=== ML-KEM Demo ===')
    mlkem_handle = None

    try:
        # Create ML-KEM primary key
        print('Creating ML-KEM-768 primary key under TPM_RH_OWNER...')
        sensitive = TPMS_SENSITIVE_CREATE()
        inPublic = build_mlkem_template(TPM_MLKEM_SECURITY_STRENGTH.MLKEM_768)

        tpm.allowErrors()
        res = tpm.CreatePrimary(
            TPM_HANDLE(TPM_RH.OWNER),
            sensitive,
            inPublic,
            b'',
            []
        )
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('CreatePrimary(MLKEM)', tpm.lastResponseCode)
            return False

        mlkem_handle = res.handle
        print(f'  ML-KEM key created, handle: 0x{int(mlkem_handle.handle):08X}')

        # Encapsulate: keyHandle only (public key operation, no auth, no scheme parameter)
        print('Running TPM2_Encapsulate...')
        tpm.allowErrors()
        enc_res = tpm.Encapsulate(mlkem_handle)
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('Encapsulate', tpm.lastResponseCode)
            return False

        # Response order per Part 3: sharedSecret first, then ciphertext
        enc_secret = enc_res.sharedSecret
        ciphertext = enc_res.ciphertext
        print(f'  Ciphertext: {len(ciphertext.buffer) if ciphertext and ciphertext.buffer else 0} bytes')
        print(f'  Encapsulated shared secret: {len(enc_secret.buffer) if enc_secret and enc_secret.buffer else 0} bytes')

        # Decapsulate: keyHandle + ciphertext (no scheme parameter)
        print('Running TPM2_Decapsulate...')
        tpm.allowErrors()
        dec_secret = tpm.Decapsulate(mlkem_handle, ciphertext)
        if tpm.lastResponseCode != TPM_RC.SUCCESS:
            _handle_unsupported('Decapsulate', tpm.lastResponseCode)
            return False

        print(f'  Decapsulated shared secret: {len(dec_secret.buffer) if dec_secret and dec_secret.buffer else 0} bytes')

        # Compare
        enc_buf = enc_secret.buffer if enc_secret else None
        dec_buf = dec_secret.buffer if dec_secret else None
        if enc_buf == dec_buf:
            print('  ML-KEM shared secrets MATCH — encapsulation/decapsulation SUCCEEDED!')
        else:
            print('  ERROR: ML-KEM shared secrets DO NOT MATCH!')
            return False

        return True

    except Exception as exc:
        print(f'  ML-KEM demo error: {exc}')
        return False

    finally:
        if mlkem_handle is not None:
            try:
                tpm.allowErrors()
                tpm.FlushContext(mlkem_handle)
            except Exception:
                pass


def _handle_unsupported(cmd_name, rc):
    """ Print a clear message when the simulator returns 'command not supported'. """
    not_supported_codes = {
        TPM_RC.COMMAND_CODE,
        TPM_RC.COMMAND_SIZE,
    }
    # Also catch command-code format errors (0x143 = RC_FMT1 | RC_P | RC_1 area)
    rc_int = int(rc)
    if int(rc) in [int(c) for c in not_supported_codes] or (rc_int & 0x0FF) == 0x043:
        print(f'  Command {cmd_name!r} is not supported by this simulator (RC={rc_int:#010x}).')
        print('  Ensure you are running a TPM 2.0 v1.85-compatible simulator.')
    else:
        print(f'  Command {cmd_name!r} failed with RC={rc_int:#010x}.')


def main():
    args = parse_args()

    print(f'Connecting to TPM simulator at {args.host}:{args.port} ...')
    tpm = Tpm(useSimulator=True, host=args.host, port=args.port)
    tpm.enableExceptions(False)

    try:
        tpm.connect()
    except Exception as exc:
        print(f'ERROR: Could not connect to simulator: {exc}')
        sys.exit(1)

    print('Connected.')

    # Initialize the simulator
    tpm.allowErrors()
    tpm.Startup(TPM_SU.CLEAR)
    if tpm.lastResponseCode not in (TPM_RC.SUCCESS, TPM_RC.INITIALIZE):
        print(f'WARNING: Startup returned unexpected code: {tpm.lastResponseCode}')

    mldsa_ok = demo_mldsa(tpm)
    mlkem_ok = demo_mlkem(tpm)

    tpm.close()

    print('\n=== Summary ===')
    print(f'  ML-DSA demo: {"PASS" if mldsa_ok else "FAIL"}')
    print(f'  ML-KEM demo: {"PASS" if mlkem_ok else "FAIL"}')

    if mldsa_ok and mlkem_ok:
        print('\nAll PQC demos completed successfully.')
        sys.exit(0)
    else:
        print('\nOne or more PQC demos failed or are not supported by this simulator.')
        sys.exit(1)


if __name__ == '__main__':
    main()
