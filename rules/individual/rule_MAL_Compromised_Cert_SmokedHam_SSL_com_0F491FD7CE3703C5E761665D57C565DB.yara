import "pe"

rule MAL_Compromised_Cert_SmokedHam_SSL_com_0F491FD7CE3703C5E761665D57C565DB {
   meta:
      description         = "Detects SmokedHam with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-16"
      version             = "1.0"

      hash                = "e9b15ced5ae1cc9f93b91f7e23beff15f2801a475cced0ef826653f3b3a89dcc"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "COMPETENT SAFETY SERVICES PRIVATE LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0f:49:1f:d7:ce:37:03:c5:e7:61:66:5d:57:c5:65:db"
      cert_thumbprint     = "D40D44DE02EECF260C11AAF6AB59F5159A9BD308"
      cert_valid_from     = "2025-10-16"
      cert_valid_to       = "2026-10-16"

      country             = "IN"
      state               = "Delhi"
      locality            = "New Delhi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0f:49:1f:d7:ce:37:03:c5:e7:61:66:5d:57:c5:65:db"
      )
}
