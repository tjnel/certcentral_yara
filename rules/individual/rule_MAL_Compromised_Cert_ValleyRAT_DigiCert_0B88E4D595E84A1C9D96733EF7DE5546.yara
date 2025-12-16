import "pe"

rule MAL_Compromised_Cert_ValleyRAT_DigiCert_0B88E4D595E84A1C9D96733EF7DE5546 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-10"
      version             = "1.0"

      hash                = "37d27fc9336fd3f8cfe7aa2250f00e4e61320aef8a39542c8eb79a853150e692"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DONGQI TRADE LIMITED"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0b:88:e4:d5:95:e8:4a:1c:9d:96:73:3e:f7:de:55:46"
      cert_thumbprint     = "8206C09E53F2378FBFC0D499B394BC89A6DD74B3"
      cert_valid_from     = "2025-10-10"
      cert_valid_to       = "2026-10-09"

      country             = "HK"
      state               = "???"
      locality            = "Tai Kok Tsui"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0b:88:e4:d5:95:e8:4a:1c:9d:96:73:3e:f7:de:55:46"
      )
}
