import "pe"

rule MAL_Compromised_Cert_Oyster_SSL_com_31D4015BD379F5DC18056F60D51A43CF {
   meta:
      description         = "Detects Oyster with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-08"
      version             = "1.0"

      hash                = "4e4a3751581252e210f6f45881d778d1f482146f92dc790504bfbcd2bdfa0129"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Art en Code B.V."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "31:d4:01:5b:d3:79:f5:dc:18:05:6f:60:d5:1a:43:cf"
      cert_thumbprint     = "A122735906981AF7D785808D27830E4894801B2D"
      cert_valid_from     = "2025-09-08"
      cert_valid_to       = "2026-09-07"

      country             = "NL"
      state               = "Noord-Holland"
      locality            = "Zwanenburg"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "31:d4:01:5b:d3:79:f5:dc:18:05:6f:60:d5:1a:43:cf"
      )
}
