import { Url } from 'url';

export interface GetIpInfoResponse {
    data: {
        type: string;
        ip: string;
        links: {
            self: Url;
        };
        attributes: {
            regional_internet_registry: string;
            jarm: string;
            network: string;
            last_https_certificate_date: number;
            tags: [];
            last_analysis_stats: LastAnalysisStats;
            last_analysis_results: LastAnalysisResults;
            last_modification_date: number;
            last_https_certificate: LastHTTPSCertificate;
            whois_date: number;
            reputation: number;
            total_votes: {
                harmless: number;
                malicious: number;
            };
            as_owner: string;
            asn: number;
            country: string;
            continent: string;
            whois: string;
        };
    };
}

interface LastAnalysisStats {
    harmless: number;
    malicious: number;
    suspicious: number;
    undetected: number;
    timeout: number;
}

interface LastAnalysisResults {
    'CMC Thread Intelligence': AnalysisResult;
    'Snort IP sample list': AnalysisResult;
    '0xSI_f33d': AnalysisResult;
    Armis: AnalysisResult;
    'Comodo Valkyrite Verdict': AnalysisResult;
    PhishLabs: AnalysisResult;
    K7AntiVirus: AnalysisResult;
    'CINS Army': AnalysisResult;
    Quttera: AnalysisResult;
    OpenPhish: AnalysisResult;
    'VX Vault': AnalysisResult;
    'Web Security Guard': AnalysisResult;
    Scantitan: AnalysisResult;
    AlienVault: AnalysisResult;
    Sophos: AnalysisResult;
    Phishtank: AnalysisResult;
    EconScope: AnalysisResult;
    Cyan: AnalysisResult;
    Spam404: AnalysisResult;
    SecureBrain: AnalysisResult;
    'Hoplite Industries': AnalysisResult;
    CRDF: AnalysisResult;
    Fortinet: AnalysisResult;
    'alphaMountain.ai': AnalysisResult;
    Lionic: AnalysisResult;
    'Virusdie External Site Scan': AnalysisResult;
    'Google Safebrowsing': AnalysisResult;
    SafeToOpen: AnalysisResult;
    ADMINUSLabs: AnalysisResult;
    CyberCrime: AnalysisResult;
    'Heimdal Security': AnalysisResult;
    AutoShun: AnalysisResult;
    Trustwave: AnalysisResult;
    'AICC (MONITORAPP)': AnalysisResult;
    CyRadar: AnalysisResult;
    'Dr.Web': AnalysisResult;
    Emsisoft: AnalysisResult;
    Abusix: AnalysisResult;
    Webroot: AnalysisResult;
    Avira: AnalysisResult;
    securolytics: AnalysisResult;
    'Antivy-AVL': AnalysisResult;
    Acronis: AnalysisResult;
    'Quick Heal': AnalysisResult;
    'ESTsecurity-Threat Inside': AnalysisResult;
    DNS8: AnalysisResult;
    'benkow.cc': AnalysisResult;
    EmergingThreats: AnalysisResult;
    'Yandex Safebrowsing': AnalysisResult;
    MalwareDomainList: AnalysisResult;
    Lumu: AnalysisResult;
    zvelo: AnalysisResult;
    Kaspersky: AnalysisResult;
    Segasec: AnalysisResult;
    'Sucuri SiteCheck': AnalysisResult;
    'desenmascara.me': AnalysisResult;
    URLhaus: AnalysisResult;
    PREBYTES: AnalysisResult;
    StopForumSpam: AnalysisResult;
    Blueliv: AnalysisResult;
    Netcraft: AnalysisResult;
    ZeroCERT: AnalysisResult;
    'Phishing Database': AnalysisResult;
    MalwarePatrol: AnalysisResult;
    MalBeacon: AnalysisResult;
    IPsum: AnalysisResult;
    Spamhaus: AnalysisResult;
    Malwared: AnalysisResult;
    BitDefender: AnalysisResult;
    GreenSnow: AnalysisResult;
    'G-Data': AnalysisResult;
    StopBadware: AnalysisResult;
    'SCUMWARE.org': AnalysisResult;
    'malwares.com URL checker': AnalysisResult;
    NotMining: AnalysisResult;
    'Forcepoint ThreadSeeker': AnalysisResult;
    Certego: AnalysisResult;
    ESET: AnalysisResult;
    Threatsourcing: AnalysisResult;
    MalSilo: AnalysisResult;
    Nucleon: AnalysisResult;
    'BADWARE.INFO': AnalysisResult;
    ThreatHive: AnalysisResult;
    FraudScore: AnalysisResult;
    Tencent: AnalysisResult;
    'Bfore.Ai PreCrime': AnalysisResult;
    'Baidu-International': AnalysisResult;
}

interface AnalysisResult {
    category: string;
    result: string;
    method: string;
    engine_name: string;
}

interface LastHTTPSCertificate {
    size: number;
    public_key: {
        rsa: {
            key_size: number;
            modulus: string;
            exponent: string;
        };
        algorithm: string;
    };
    thumbprint_sha256: string;
    tags: [];
    cert_signature: {
        signature: string;
        signature_algorithm: string;
    };
    validity: {
        not_after: Date;
        not_before: Date;
    };
    version: string;
    extensions: {
        certificate_polocies: string[];
        extended_key_usage: string[];
        authority_key_identifier: {
            keyid: string;
        };
        subject_alternative_name: string[];
        tags: [];
        subject_key_identifier: string;
        crl_distribution_points: Url[];
        Key_usage: string[];
        CA: boolean;
        ca_information_access: {
            'CA Issuers': Url;
            OCSP: Url;
        };
    };
    signature_algorithm: string;
    serial_number: string;
    thumbprint: string;
    issuer: {
        C: string;
        CN: string;
        O: string;
    };
    subject: {
        CN: string;
    };
}
