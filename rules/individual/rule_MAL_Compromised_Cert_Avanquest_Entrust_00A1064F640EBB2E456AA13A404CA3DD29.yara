import "pe"

rule MAL_Compromised_Cert_Avanquest_Entrust_00A1064F640EBB2E456AA13A404CA3DD29 {
   meta:
      description         = "Detects Avanquest with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-20"
      version             = "1.0"

      hash                = "b1897903de6f882f17118e5ecb43e4a6e56917f972a3a64ca6aa50eae8adc4c5"
      malware             = "Avanquest"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PC Helpsoft (7270356 Canada Inc)"
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "00:a1:06:4f:64:0e:bb:2e:45:6a:a1:3a:40:4c:a3:dd:29"
      cert_thumbprint     = "D518B348DD0D9EE55A1BF422D8C07E4FAD64383F"
      cert_valid_from     = "2025-06-20"
      cert_valid_to       = "2026-06-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "00:a1:06:4f:64:0e:bb:2e:45:6a:a1:3a:40:4c:a3:dd:29"
      )
}
