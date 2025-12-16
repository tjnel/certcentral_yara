import "pe"

rule MAL_Compromised_Cert_RDPWrap_DigiCert_096473E3991014691A73038C059A866E {
   meta:
      description         = "Detects RDPWrap with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-29"
      version             = "1.0"

      hash                = "70c7f64eadfade752b92f336bcf80a52266ed908ce3fc4000f91533f91f71f46"
      malware             = "RDPWrap"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CTY TNHH MOT THANH VIEN THUONG MAI DICH VU TAM TAI"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "09:64:73:e3:99:10:14:69:1a:73:03:8c:05:9a:86:6e"
      cert_thumbprint     = "D5D40096B4D3863D404B54730859EC87575E1816"
      cert_valid_from     = "2025-04-29"
      cert_valid_to       = "2026-04-28"

      country             = "VN"
      state               = "Thua Thien Hue"
      locality            = "Thuan Hoa"
      email               = "???"
      rdn_serial_number   = "3301565601"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "09:64:73:e3:99:10:14:69:1a:73:03:8c:05:9a:86:6e"
      )
}
