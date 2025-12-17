import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_611E5DC57B210DC08205140F6D57063F {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-11"
      version             = "1.0"

      hash                = "f7dea7d5f87f19c73def52f3b40ca9f0c903a82d49fccb65d3acc1c4f12ad17c"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ASTRA PROPERTY MANAGEMENT, SRL"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "61:1e:5d:c5:7b:21:0d:c0:82:05:14:0f:6d:57:06:3f"
      cert_thumbprint     = "63FE755BD074ADE6D50DECEF81004F9FE8BA8CA7"
      cert_valid_from     = "2025-08-11"
      cert_valid_to       = "2026-08-11"

      country             = "MD"
      state               = "Bălți Municipality"
      locality            = "Bălţi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "61:1e:5d:c5:7b:21:0d:c0:82:05:14:0f:6d:57:06:3f"
      )
}
