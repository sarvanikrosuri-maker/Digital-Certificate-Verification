module hrithvika_addr::CertificateVerification {
    use aptos_framework::signer;
    use std::string::String;
    use std::vector;
    use aptos_framework::timestamp;

    /// Struct representing a digital certificate
    struct Certificate has store, key, copy, drop {
        certificate_id: String,      // Unique certificate identifier
        recipient_name: String,      // Name of certificate recipient
        institution: address,        // Address of issuing institution
        issue_date: u64,            // Timestamp when certificate was issued
        is_revoked: bool,           // Whether certificate has been revoked
        certificate_hash: String,    // Hash for verification purposes
    }

    /// Struct to store all certificates issued by an institution
    struct CertificateRegistry has key {
        certificates: vector<Certificate>,
    }

    /// Error codes
    const E_NOT_AUTHORIZED: u64 = 1;
    const E_CERTIFICATE_NOT_FOUND: u64 = 2;
    const E_ALREADY_REVOKED: u64 = 3;

    /// Function to issue a new certificate
    public fun issue_certificate(
        issuer: &signer,
        certificate_id: String,
        recipient_name: String,
        certificate_hash: String
    ) acquires CertificateRegistry {
        let issuer_addr = signer::address_of(issuer);
        
        // Create new certificate
        let new_certificate = Certificate {
            certificate_id,
            recipient_name,
            institution: issuer_addr,
            issue_date: timestamp::now_seconds(),
            is_revoked: false,
            certificate_hash,
        };

        // Check if registry exists, if not create it
        if (!exists<CertificateRegistry>(issuer_addr)) {
            let registry = CertificateRegistry {
                certificates: vector::empty<Certificate>(),
            };
            move_to(issuer, registry);
        };

        // Add certificate to registry
        let registry = borrow_global_mut<CertificateRegistry>(issuer_addr);
        vector::push_back(&mut registry.certificates, new_certificate);
    }

    /// Function to verify a certificate by its ID and issuer address
    public fun verify_certificate(
        institution_addr: address,
        certificate_id: String
    ): (bool, String, u64, bool) acquires CertificateRegistry {
        // Check if institution has issued any certificates
        if (!exists<CertificateRegistry>(institution_addr)) {
            return (false, std::string::utf8(b""), 0, true)
        };

        let registry = borrow_global<CertificateRegistry>(institution_addr);
        let certificates = &registry.certificates;
        let len = vector::length(certificates);
        let i = 0;

        // Search for certificate by ID
        while (i < len) {
            let cert = vector::borrow(certificates, i);
            if (cert.certificate_id == certificate_id) {
                return (true, cert.recipient_name, cert.issue_date, cert.is_revoked)
            };
            i = i + 1;
        };

        // Certificate not found
        (false, std::string::utf8(b""), 0, true)
    }
}