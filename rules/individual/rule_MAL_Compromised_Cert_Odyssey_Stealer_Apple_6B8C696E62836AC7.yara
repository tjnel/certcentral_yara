import "pe"

rule MAL_Compromised_Cert_Odyssey_Stealer_Apple_6B8C696E62836AC7 {
   meta:
      description         = "Detects Odyssey Stealer with compromised cert (Apple)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "a031ba8111ded0c11acfedea9ab83b4be8274584da71bcc88ff72e2d51957dd7"
      malware             = "Odyssey Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THOMAS BOULAY DUVAL"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "6b:8c:69:6e:62:83:6a:c7"
      cert_thumbprint     = "FE168DBB8B78694EF58D02CE89D50B30DF6CE82D"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2027-02-01"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "6b:8c:69:6e:62:83:6a:c7"
      )
}
