import "pe"

rule MAL_Compromised_Cert_DarkGate_GlobalSign_4BC418BDB4B1330B041BE689 {
   meta:
      description         = "Detects DarkGate with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-24"
      version             = "1.0"

      hash                = "1ffa8b06cb779360f8c42ccd4527ae3076d25d11b3a90976f04ea430173e9b85"
      malware             = "DarkGate"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware was known to be multifunctional and evasive. Its main popularity was in 2024 during a period where there were open sales. See this for more information on its functionality: https://www.proofpoint.com/us/blog/email-and-cloud-threats/darkgate-malware"

      signer              = "Technic AS Plus Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4b:c4:18:bd:b4:b1:33:0b:04:1b:e6:89"
      cert_thumbprint     = "F8E657AB86105C880CACACC939661F85E24769AF"
      cert_valid_from     = "2024-12-24"
      cert_valid_to       = "2025-12-25"

      country             = "CA"
      state               = "Quebec"
      locality            = "Montreal"
      email               = "???"
      rdn_serial_number   = "920816-0"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4b:c4:18:bd:b4:b1:33:0b:04:1b:e6:89"
      )
}
