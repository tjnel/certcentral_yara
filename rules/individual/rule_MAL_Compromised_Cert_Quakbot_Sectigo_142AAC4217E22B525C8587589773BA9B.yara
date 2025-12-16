import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_142AAC4217E22B525C8587589773BA9B {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-24"
      version             = "1.0"

      hash                = "f543e03f714e5105b167fbddfe2112f0decaa3521971ed88f631dbca39caf8f2"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "A.B. gostinstvo trgovina posredništvo in druge storitve, d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b"
      cert_thumbprint     = "B15A4189DCBB27F9B7CED94BC5CA40B7E62135C3"
      cert_valid_from     = "2021-02-24"
      cert_valid_to       = "2022-02-24"

      country             = "SI"
      state               = "???"
      locality            = "Maribor"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b"
      )
}
