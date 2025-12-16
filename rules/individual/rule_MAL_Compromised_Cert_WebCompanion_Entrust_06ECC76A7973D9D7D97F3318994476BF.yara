import "pe"

rule MAL_Compromised_Cert_WebCompanion_Entrust_06ECC76A7973D9D7D97F3318994476BF {
   meta:
      description         = "Detects WebCompanion with compromised cert (Entrust)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-02"
      version             = "1.0"

      hash                = "af347c357858ad3d468614b35930b2f56c31acbcdc0fa5f36788513b58702710"
      malware             = "WebCompanion"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "7270356 Canada Inc."
      cert_issuer_short   = "Entrust"
      cert_issuer         = "Entrust Extended Validation Code Signing CA - EVCS2"
      cert_serial         = "06:ec:c7:6a:79:73:d9:d7:d9:7f:33:18:99:44:76:bf"
      cert_thumbprint     = "56F38BE28047D9123F6DC63C0F26D557F815011F"
      cert_valid_from     = "2025-04-02"
      cert_valid_to       = "2026-04-02"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Entrust Extended Validation Code Signing CA - EVCS2" and
         sig.serial == "06:ec:c7:6a:79:73:d9:d7:d9:7f:33:18:99:44:76:bf"
      )
}
