import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_009211EB6FADC4800F3FB2A49230C8FC62 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-08"
      version             = "1.0"

      hash                = "415b6d1bb78cb74a468b29e7af09e885999cfcabf2c413f3bf533c2191d4e626"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mainstay Crypto LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:92:11:eb:6f:ad:c4:80:0f:3f:b2:a4:92:30:c8:fc:62"
      cert_thumbprint     = "C0A01D5A2401E3FBB83118A16DAEC0DBAA5B454A"
      cert_valid_from     = "2025-01-08"
      cert_valid_to       = "2026-01-08"

      country             = "US"
      state               = "New Hampshire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:92:11:eb:6f:ad:c4:80:0f:3f:b2:a4:92:30:c8:fc:62"
      )
}
