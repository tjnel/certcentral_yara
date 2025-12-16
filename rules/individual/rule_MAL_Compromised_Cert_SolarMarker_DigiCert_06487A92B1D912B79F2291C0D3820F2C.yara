import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_06487A92B1D912B79F2291C0D3820F2C {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-10-04"
      version             = "1.0"

      hash                = "a8b1ff391ff0937a12b63d34b6a8326bf5058e0a2ac9ae5306ed8d708f1e6e44"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Soto Manufacturing SRL"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:48:7a:92:b1:d9:12:b7:9f:22:91:c0:d3:82:0f:2c"
      cert_thumbprint     = "AEE8241A17357D5713C451406BA4D3FBDCC1E25F"
      cert_valid_from     = "2021-10-04"
      cert_valid_to       = "2023-08-04"

      country             = "RO"
      state               = "???"
      locality            = "CUGIR"
      email               = "???"
      rdn_serial_number   = "J01/119/2017"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:48:7a:92:b1:d9:12:b7:9f:22:91:c0:d3:82:0f:2c"
      )
}
