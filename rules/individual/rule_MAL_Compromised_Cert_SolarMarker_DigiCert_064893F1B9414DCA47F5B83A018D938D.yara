import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_064893F1B9414DCA47F5B83A018D938D {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-08"
      version             = "1.0"

      hash                = "f61f2dc8346f3777b4210ecc84ec55a909666a38796124172317007041a17030"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Stratos Digital Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:48:93:f1:b9:41:4d:ca:47:f5:b8:3a:01:8d:93:8d"
      cert_thumbprint     = "F4A1423AF3BCE54A419E6148E6D1AFD537687932"
      cert_valid_from     = "2021-09-08"
      cert_valid_to       = "2022-09-08"

      country             = "IE"
      state               = "???"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "702708"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:48:93:f1:b9:41:4d:ca:47:f5:b8:3a:01:8d:93:8d"
      )
}
