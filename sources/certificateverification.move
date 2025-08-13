module hrithvika_addr::CertificateVerification {
    use aptos_framework::signer;
    use std::string::String;
    use std::vector;
    use aptos_framework::timestamp;

   
    struct Certificate has store, key, copy, drop {
        certificate_id: String,      
        recipient_name: String,      
        institution: address,        
        issue_date: u64,            
        is_revoked: bool,           
        certificate_hash: String,    
    }

    
    struct CertificateRegistry has key {
        certificates: vector<Certificate>,
    }

   
    const E_NOT_AUTHORIZED: u64 = 1;
    const E_CERTIFICATE_NOT_FOUND: u64 = 2;
    const E_ALREADY_REVOKED: u64 = 3;

    
    public fun issue_certificate(
        issuer: &signer,
        certificate_id: String,
        recipient_name: String,
        certificate_hash: String
    ) acquires CertificateRegistry {
        let issuer_addr = signer::address_of(issuer);
        
        
        let new_certificate = Certificate {
            certificate_id,
            recipient_name,
            institution: issuer_addr,
            issue_date: timestamp::now_seconds(),
            is_revoked: false,
            certificate_hash,
        };

        
        if (!exists<CertificateRegistry>(issuer_addr)) {
            let registry = CertificateRegistry {
                certificates: vector::empty<Certificate>(),
            };
            move_to(issuer, registry);
        };

        
        let registry = borrow_global_mut<CertificateRegistry>(issuer_addr);
        vector::push_back(&mut registry.certificates, new_certificate);
    }

    
    public fun verify_certificate(
        institution_addr: address,
        certificate_id: String
    ): (bool, String, u64, bool) acquires CertificateRegistry {
        
        if (!exists<CertificateRegistry>(institution_addr)) {
            return (false, std::string::utf8(b""), 0, true)
        };

        let registry = borrow_global<CertificateRegistry>(institution_addr);
        let certificates = &registry.certificates;
        let len = vector::length(certificates);
        let i = 0;

        
        while (i < len) {
            let cert = vector::borrow(certificates, i);
            if (cert.certificate_id == certificate_id) {
                return (true, cert.recipient_name, cert.issue_date, cert.is_revoked)
            };
            i = i + 1;
        };

        
        (false, std::string::utf8(b""), 0, true)
    }

}
