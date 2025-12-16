import "pe"

rule MAL_Compromised_Cert_BitRAT_DigiCert_0F007898AFCBA5F8AF8AE65D01803617 {
   meta:
      description         = "Detects BitRAT with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-14"
      version             = "1.0"

      hash                = "8c1ec43b6a766a95c0d1b94fe24418541c8a8858847dff24334eab95e9c117e0"
      malware             = "BitRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TechnoElek s.r.o."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17"
      cert_thumbprint     = "5687481A453414E63E76E1135ED53F4BD0410B05"
      cert_valid_from     = "2021-04-14"
      cert_valid_to       = "2022-04-11"

      country             = "SK"
      state               = "???"
      locality            = "Bratislava"
      email               = "???"
      rdn_serial_number   = "52 253 228"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17"
      )
}
