import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_35769C2B094E3469AEF8193D6188F341 {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-15"
      version             = "1.0"

      hash                = "88e9c1f5026834ebcdaed98f56d52b5f23547ac2c03aa43c5e50e7d8e1b82b3a"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Art en Code B.V."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "35:76:9c:2b:09:4e:34:69:ae:f8:19:3d:61:88:f3:41"
      cert_thumbprint     = "E01B1C0B5488998AA7BE21464C67A45D873C8B3D"
      cert_valid_from     = "2025-09-15"
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
         sig.serial == "35:76:9c:2b:09:4e:34:69:ae:f8:19:3d:61:88:f3:41"
      )
}
